//! A mock HSPO driver end to end under an accounting driver: a robot thread
//! streams position datagrams every 5 ms, the driver thread pins itself,
//! tunes its NIC, watches its socket with a monitor and reads kernel
//! stamps, and the test seeds the environment and reads everything back.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime};

use snare::fast_talker::monitor::{Config as MonitorConfig, Monitor, Sample, WatchedSocket};
use snare::fast_talker::nic::Nic;
use snare::fast_talker::rt::{self, CpuDmaLatency, Scheduler};
use snare::fast_talker::sim;
use snare::fast_talker::sockets::SocketOptions;
use snare::fast_talker::{Config, Hardware, Received, Source, Timestamped, compat};
use snare::net::UdpSocket;
use snare::sched::{self, Driver, DriverConfig, ThreadClass};
use snare::{
    IpNet, NicSpec, OsSemantics, SocketId, add_nic, inject_socket_drops, inject_udp_from_test,
    nic_counters, register_test, set_nic_policy, set_os_semantics, set_udp_policy, socket_entry,
    socket_id,
};

const DRIVER: &str = "10.1.0.1:60015";
const ROBOT: &str = "10.1.0.2:60015";
const PERIOD: Duration = Duration::from_millis(5);
const FRAMES: u64 = 40;
const WIRE: Duration = Duration::from_micros(100);
const NIC_LATENCY: Duration = Duration::from_micros(50);
const LOST: [u64; 2] = [10, 11];
const INJECT_AT: u64 = 20;
const INJECTED: u32 = 3;
const MONITOR_EVERY: Duration = Duration::from_millis(20);
const WAIT: Duration = Duration::from_secs(20);

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

struct Clock {
    driver: Arc<Driver>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Clock {
    fn start() -> Self {
        let driver = Arc::new(
            sched::attach_driver(DriverConfig {
                seed: 7,
                accounting: true,
                audit: true,
            })
            .unwrap(),
        );
        sched::mark_background("hspo-e2e-main");
        let stop = Arc::new(AtomicBool::new(false));
        let parent = std::thread::current().id();
        let thread = {
            let driver = Arc::clone(&driver);
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                snare::register_thread_child_of(parent);
                sched::mark_driver_thread();
                while !stop.load(Ordering::Acquire) {
                    let q = driver.quiescence();
                    if q.quiescent
                        && let Some(d) = q.next_deadline
                    {
                        let _ = driver.jump_to(d);
                        continue;
                    }
                    std::thread::sleep(Duration::from_micros(200));
                }
            })
        };
        Self {
            driver,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Clock {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

struct Run {
    rx: Timestamped<UdpSocket>,
    got: Vec<(u64, Received)>,
    hw_error: io::Error,
    samples: Vec<Sample>,
}

fn hspo_driver(ready: mpsc::Sender<SocketId>, robot_done: Arc<AtomicBool>) -> Run {
    let me = rt::Thread::current();
    me.pin_scheduler(&[3], Scheduler::Fifo(80)).unwrap();
    rt::lock_memory().unwrap();
    rt::prefault_stack(256 * 1024);
    let dma = CpuDmaLatency::request(Duration::ZERO).unwrap();

    let nic = Nic::open("eth1").unwrap();
    let mut rings = nic.rings().unwrap();
    rings.rx = 4096;
    nic.set_rings(&rings).unwrap();
    let mut coalesce = nic.coalesce().unwrap();
    coalesce.rx_usecs = 0;
    coalesce.adaptive_rx = false;
    nic.set_coalesce(&coalesce).unwrap();
    nic.set_threaded_napi(true).unwrap();
    nic.set_irq_affinity(&[2]).unwrap();

    let sock = UdpSocket::bind(DRIVER).unwrap();
    SocketOptions {
        recv_buffer: Some(4 << 20),
        ..SocketOptions::default()
    }
    .apply(&sock)
    .unwrap();
    sock.set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    let hw_error = Timestamped::try_with_config(
        UdpSocket::bind("10.1.0.1:0").unwrap(),
        Config {
            hardware: Hardware::Interface("eth1".into()),
            ..Config::default()
        },
    )
    .unwrap_err();
    let rx = Timestamped::new(sock);

    let (samples_tx, samples_rx) = mpsc::channel::<Sample>();
    let monitor = Monitor::start(
        MonitorConfig {
            interval: MONITOR_EVERY,
            interfaces: vec!["eth1".into()],
            sockets: vec![WatchedSocket::new("hspo", rx.get_ref()).unwrap()],
            ..MonitorConfig::default()
        },
        move |s| {
            let _ = samples_tx.send(s.clone());
        },
    )
    .unwrap();

    ready.send(socket_id(rx.get_ref())).unwrap();
    let mut buf = [0u8; 64];
    let mut got = Vec::new();
    loop {
        match rx.recv_from(&mut buf) {
            Ok(r) => {
                let seq = u64::from_le_bytes(buf[..8].try_into().unwrap());
                got.push((seq, r));
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                if robot_done.load(Ordering::Acquire) {
                    break;
                }
            }
            Err(e) => panic!("recv: {e}"),
        }
    }
    monitor.stop();
    drop(dma);
    Run {
        rx,
        got,
        hw_error,
        samples: samples_rx.try_iter().collect(),
    }
}

fn robot(id: SocketId, done: Arc<AtomicBool>) -> Vec<SystemTime> {
    let mut sent = Vec::new();
    for seq in 0..FRAMES {
        if seq == LOST[0] {
            set_udp_policy(addr(DRIVER), |p| p.loss_rate = 1.0);
        }
        if seq == LOST[1] + 1 {
            set_udp_policy(addr(DRIVER), |p| p.loss_rate = 0.0);
        }
        if seq == INJECT_AT {
            inject_socket_drops(id, INJECTED).unwrap();
        }
        sent.push(compat::now());
        inject_udp_from_test(addr(ROBOT), addr(DRIVER), seq.to_le_bytes().to_vec());
        snare::thread::sleep(PERIOD);
    }
    done.store(true, Ordering::Release);
    sent
}

fn drops_before(seq: u64) -> u32 {
    let lost = LOST.iter().filter(|&&l| l < seq).count() as u32;
    lost + if seq >= INJECT_AT { INJECTED } else { 0 }
}

#[test]
fn an_hspo_driver_is_stamped_counted_and_fully_observable() {
    register_test();
    set_os_semantics(OsSemantics::Linux);
    add_nic(NicSpec::new("eth1").address("10.1.0.1/24".parse::<IpNet>().unwrap())).unwrap();
    set_nic_policy("eth1", |p| p.latency = NIC_LATENCY).unwrap();
    set_udp_policy(addr(DRIVER), |p| p.inbound_latency = WIRE);

    let clock = Clock::start();
    let robot_done = Arc::new(AtomicBool::new(false));
    let (ready_tx, ready_rx) = mpsc::channel();
    let driver = {
        let done = Arc::clone(&robot_done);
        snare::thread::Builder::new()
            .name("hspo-rx".into())
            .spawn(move || hspo_driver(ready_tx, done))
            .unwrap()
    };
    let id = ready_rx.recv_timeout(WAIT).unwrap();

    let held = sim::process();
    assert!(held.memory_locked);
    assert_eq!(held.dma_latency_effective, Some(Duration::ZERO));
    let names: Vec<String> = clock
        .driver
        .participants()
        .iter()
        .map(|p| p.name.to_string())
        .collect();
    assert!(names.iter().any(|n| n == "hspo-rx"), "{names:?}");

    let robot = {
        let done = Arc::clone(&robot_done);
        snare::thread::Builder::new()
            .name("robot".into())
            .spawn(move || robot(id, done))
            .unwrap()
    };
    let sent = robot.join().unwrap();
    let run = driver.join().unwrap();
    let audit = clock.driver.audit();
    let participants_at_end = clock.driver.participants();
    drop(clock);

    assert_eq!(run.hw_error.kind(), io::ErrorKind::Unsupported);
    assert_eq!(run.rx.source(), Source::Kernel);
    assert_eq!(run.rx.hardware_interface(), None);

    let want: Vec<u64> = (0..FRAMES).filter(|s| !LOST.contains(s)).collect();
    assert_eq!(run.got.iter().map(|(s, _)| *s).collect::<Vec<_>>(), want);
    for (seq, r) in &run.got {
        let seq = *seq;
        assert_eq!(r.from, addr(ROBOT));
        assert_eq!(r.len, 8);
        assert_eq!(r.timestamp.source, Source::Kernel);
        assert_eq!(r.timestamp.hardware_raw, None);
        assert_eq!(
            r.timestamp.time,
            sent[seq as usize] + WIRE + NIC_LATENCY,
            "frame {seq}"
        );
        assert_eq!(r.drops, Some(drops_before(seq)), "frame {seq}");
    }
    for pair in sent.windows(2) {
        assert_eq!(pair[1].duration_since(pair[0]).unwrap(), PERIOD);
    }

    let entry = socket_entry(id).unwrap();
    assert_eq!(entry.wire_lost, LOST.len() as u64);
    assert_eq!(entry.drops, LOST.len() as u32 + INJECTED);
    assert_eq!(entry.delivered, want.len() as u64);
    assert_eq!(entry.overflowed, 0);
    assert_eq!(entry.nic.as_deref(), Some("eth1"));
    assert_eq!(entry.last_rx_nic.as_deref(), Some("eth1"));
    let counters = nic_counters("eth1").unwrap();
    assert_eq!(counters.rx_packets, want.len() as u64);
    assert_eq!(counters.rx_bytes, 8 * want.len() as u64);
    assert_eq!(counters.rx_dropped, LOST.len() as u64);

    let ft = sim::socket(id).unwrap();
    assert_eq!(ft.options.recv_buffer, Some(4 << 20));
    assert_eq!(ft.sockopts.recv_buffer, Some(8 << 20));
    assert_eq!(ft.source, Some(Source::Kernel));
    assert!(ft.timestamping.is_some());
    assert_eq!(ft.hardware_interface, None);

    let hspo = sim::thread_named("hspo-rx").unwrap();
    assert_eq!(hspo.scheduler, Some(Scheduler::Fifo(80)));
    assert_eq!(hspo.affinity.as_deref(), Some(&[3][..]));
    assert_eq!(hspo.prefault_bytes, 256 * 1024);
    assert_eq!(hspo.class, ThreadClass::Participant);
    assert!(hspo.log.iter().all(|a| a.result.is_ok()), "{:?}", hspo.log);
    let robot_thread = sim::thread_named("robot").unwrap();
    assert_eq!(robot_thread.scheduler, None);

    let process = sim::process();
    assert!(process.memory_locked);
    assert!(process.dma_latency.is_empty());
    assert!(
        process
            .log
            .iter()
            .any(|a| a.what.starts_with("CpuDmaLatency::request") && a.result.is_ok())
    );

    let iface = sim::interface("eth1").unwrap();
    assert!(iface.link_up);
    assert_eq!(iface.settings.rings.rx, 4096);
    assert_eq!(iface.settings.coalesce.rx_usecs, 0);
    assert!(!iface.settings.coalesce.adaptive_rx);
    assert!(iface.settings.threaded_napi);
    assert!(!iface.settings.hw_rx_timestamping);
    assert!(!iface.irqs.is_empty());
    for n in &iface.irqs {
        assert_eq!(sim::irq(*n).unwrap().affinity, vec![2]);
    }
    assert!(iface.apply_log.iter().all(|a| a.result.is_ok()));

    let monitors = sim::monitors();
    assert_eq!(monitors.len(), 1);
    let m = &monitors[0];
    assert_eq!(m.interval, MONITOR_EVERY);
    assert_eq!(m.interfaces, vec!["eth1".to_string()]);
    assert_eq!(m.sockets, vec![("hspo".to_string(), id, false)]);
    assert!(m.stopped_at.is_some());
    assert_eq!(m.samples, run.samples.len() as u64);
    let mon = sim::thread_by_tid(m.thread_tid.unwrap()).unwrap();
    assert_eq!(mon.name.as_deref(), Some("fast-talker-mon"));
    assert_eq!(mon.class, ThreadClass::Background);
    assert!(mon.exited);

    assert!(run.samples.len() >= 5, "{}", run.samples.len());
    for pair in run.samples.windows(2) {
        assert_eq!(pair[1].sequence, pair[0].sequence + 1);
        assert_eq!(
            pair[1].time.duration_since(pair[0].time).unwrap(),
            MONITOR_EVERY
        );
        assert_eq!(pair[1].elapsed, MONITOR_EVERY);
    }
    let sampled_drops: u32 = run.samples.iter().filter_map(|s| s.sockets[0].drops).sum();
    assert_eq!(sampled_drops, LOST.len() as u32 + INJECTED);
    let sampled_rx: u64 = run
        .samples
        .iter()
        .filter_map(|s| s.interfaces[0].link_delta.as_ref())
        .map(|d| d.rx_packets)
        .sum();
    assert_eq!(sampled_rx, want.len() as u64);
    assert!(run.samples.iter().all(|s| s.errors.is_empty()));

    assert!(audit.violations.is_empty(), "{:?}", audit.violations);
    assert!(
        audit
            .class_effects
            .iter()
            .any(|e| &*e.thread == "fast-talker-mon" && e.class == ThreadClass::Background),
        "{:?}",
        audit.class_effects
    );
    assert!(
        participants_at_end
            .iter()
            .all(|p| &*p.name != "fast-talker-mon")
    );
}
