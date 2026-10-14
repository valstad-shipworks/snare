//! The traffic of a two-arm robot cell under an executive, shaped like a hardware-in-the-loop
//! simulator that drives a real controller stack against emulated devices: an executive outside
//! the sim owns its clock and runs a timestamp every 4 ms (and every 5 ms for a seam sensor),
//! entering each only once the sim is quiescent, as sham's executive does. At each timestamp it
//! drains the motion commands a device reactor queued and hands the replies to a courier thread.
//! Inside the sim, the device side is one reactor blocked in `poll` over every device socket and
//! one courier parked in `snare::sched::park`; the driver side is a mio loop per streaming port,
//! request/reply clients on TCP, a 2 ms receive-timeout poller and a 4 ms bus master.
//!
//! Sockets: 14 UDP and 15 TCP (5 listeners, 10 connections). Payloads are 16 B to 1 KiB, except a
//! 5 KiB seam frame every 5 ms.
//!
//! Prints the wall time the sim took for its virtual time and how often the executive checked,
//! waited, jumped and entered.
//!
//! On Windows the device reactor waits in `WSAPoll`, and the bus master's wake is a connected UDP
//! pair in place of a Unix datagram pair: two UDP sockets more.
//!
//! Run with: `cargo bench -p snare --bench cell_workload [-- SIM_SECS]`

#[cfg(any(unix, windows))]
mod cell {
    use std::collections::VecDeque;
    use std::io::{ErrorKind, Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream, UdpSocket};
    #[cfg(unix)]
    use std::os::fd::{AsRawFd as AsRaw, RawFd as Raw};
    #[cfg(windows)]
    use std::os::windows::io::{AsRawSocket as AsRaw, RawSocket as Raw};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::{Duration, Instant};

    use snare::Sim;
    use snare::sched::{self, ExecutiveConfig, Unparker};

    const MS: Duration = Duration::from_millis(1);
    const ARMS: usize = 2;
    const STMO_PERIOD: Duration = Duration::from_millis(8);
    const HSPO_PERIOD: Duration = Duration::from_millis(4);
    const SEAM_PERIOD: Duration = Duration::from_millis(5);
    const STMO_STATUS: usize = 132;
    const STMO_COMMAND: usize = 104;
    const HSPO_JOINTS: usize = 60;
    const HSPO_VARIABLES: usize = 54;
    const SEAM_FRAME: usize = 5200;
    const RMI_REQUEST: usize = 200;
    const RMI_REPLY: usize = 260;
    const HMI_MESSAGE: usize = 64;
    const BUS_FRAME: usize = 64;
    const ARC_FEEDBACK: usize = 120;

    fn stmo_addr(arm: usize) -> SocketAddr {
        SocketAddr::from(([127, 0, 1, 1 + arm as u8], 60015))
    }
    fn rmi_addr(arm: usize) -> SocketAddr {
        SocketAddr::from(([127, 0, 1, 1 + arm as u8], 16002))
    }
    fn hmi_addr(arm: usize) -> SocketAddr {
        SocketAddr::from(([127, 0, 1, 1 + arm as u8], 60008))
    }
    fn hspo_source(arm: usize) -> SocketAddr {
        SocketAddr::from(([127, 0, 1, 1 + arm as u8], 15001))
    }
    const HSPO_BROKER: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 3, 240), 15000));
    const SEAM: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 4, 1), 32001));
    const GVCP: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 5, 1), 3956));
    const ARC_DEVICE: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 2, 1), 4323));
    const BUS_EMULATOR: SocketAddr =
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 6, 1), 34980));

    #[derive(Default)]
    struct Counts {
        stmo_commands: AtomicU64,
        stmo_statuses: AtomicU64,
        hspo: AtomicU64,
        hspo_received: AtomicU64,
        seam_bytes: AtomicU64,
        rmi: AtomicU64,
        arc: AtomicU64,
        bus: AtomicU64,
        gvcp: AtomicU64,
    }

    enum Job {
        Status(usize, SocketAddr),
        Hspo(usize),
        Seam,
    }

    struct Courier {
        jobs: Mutex<VecDeque<Job>>,
        unparker: Unparker,
    }

    impl Courier {
        fn post(&self, job: Job) {
            let mut jobs = self.jobs.lock().unwrap();
            let was_empty = jobs.is_empty();
            jobs.push_back(job);
            drop(jobs);
            if was_empty {
                self.unparker.unpark();
            }
        }
    }

    struct Device {
        stmo: Vec<UdpSocket>,
        hspo: Vec<UdpSocket>,
        seam: Mutex<Option<TcpStream>>,
        inbox: Vec<Mutex<VecDeque<SocketAddr>>>,
        counts: Arc<Counts>,
    }

    fn raw(socket: &impl AsRaw) -> Raw {
        #[cfg(unix)]
        return socket.as_raw_fd();
        #[cfg(windows)]
        return socket.as_raw_socket();
    }

    /// Waits up to `timeout_ms` (for good if negative) until one of `sockets` is readable,
    /// returning whether each is.
    #[cfg(unix)]
    fn readable(sockets: &[Raw], timeout_ms: i32) -> Vec<bool> {
        let mut fds: Vec<libc::pollfd> = sockets
            .iter()
            .map(|&fd| libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            })
            .collect();
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) };
        assert!(n >= 0, "poll: {}", std::io::Error::last_os_error());
        fds.iter().map(|fd| fd.revents != 0).collect()
    }

    #[cfg(windows)]
    fn readable(sockets: &[Raw], timeout_ms: i32) -> Vec<bool> {
        use windows_sys::Win32::Networking::WinSock::{POLLRDNORM, WSAPOLLFD, WSAPoll};
        let mut fds: Vec<WSAPOLLFD> = sockets
            .iter()
            .map(|&fd| WSAPOLLFD {
                fd: fd as usize,
                events: POLLRDNORM,
                revents: 0,
            })
            .collect();
        let n = unsafe { WSAPoll(fds.as_mut_ptr(), fds.len() as u32, timeout_ms) };
        assert!(n >= 0, "WSAPoll: {}", std::io::Error::last_os_error());
        fds.iter().map(|fd| fd.revents != 0).collect()
    }

    fn spawn(name: &str, f: impl FnOnce() + Send + 'static) {
        thread::Builder::new().name(name.into()).spawn(f).unwrap();
    }

    fn reactor(
        device: Arc<Device>,
        rmi: Vec<TcpListener>,
        hmi: Vec<TcpListener>,
        seam: TcpListener,
        gvcp: UdpSocket,
    ) {
        for s in &device.stmo {
            s.set_nonblocking(true).unwrap();
        }
        for l in rmi.iter().chain(&hmi).chain([&seam]) {
            l.set_nonblocking(true).unwrap();
        }
        gvcp.set_nonblocking(true).unwrap();
        let mut conns: Vec<(TcpStream, usize)> = Vec::new();
        let mut buf = vec![0u8; 2048];
        let reply_rmi = [b'r'; RMI_REPLY];
        let reply_hmi = [b'h'; HMI_MESSAGE];
        loop {
            let mut fds = Vec::new();
            fds.extend(device.stmo.iter().map(raw));
            fds.extend(rmi.iter().chain(&hmi).map(raw));
            fds.push(raw(&seam));
            fds.push(raw(&gvcp));
            fds.extend(conns.iter().map(|(c, _)| raw(c)));
            let fds = readable(&fds, -1);
            let ready = |i: usize| fds[i];
            let polled = conns.len();
            for arm in 0..ARMS {
                if ready(arm) {
                    while let Ok((_, from)) = device.stmo[arm].recv_from(&mut buf) {
                        device.inbox[arm].lock().unwrap().push_back(from);
                    }
                }
            }
            for (i, l) in rmi.iter().chain(&hmi).enumerate() {
                if ready(ARMS + i) {
                    while let Ok((c, _)) = l.accept() {
                        c.set_nonblocking(true).unwrap();
                        c.set_nodelay(true).unwrap();
                        conns.push((c, usize::from(i >= ARMS)));
                    }
                }
            }
            let at = ARMS + 2 * ARMS;
            if ready(at)
                && let Ok((c, _)) = seam.accept()
            {
                c.set_nodelay(true).unwrap();
                *device.seam.lock().unwrap() = Some(c);
            }
            if ready(at + 1) {
                while let Ok((n, from)) = gvcp.recv_from(&mut buf) {
                    let _ = gvcp.send_to(&buf[..n], from);
                }
            }
            for (i, (conn, kind)) in conns.iter_mut().enumerate().take(polled) {
                if !ready(at + 2 + i) {
                    continue;
                }
                loop {
                    match conn.read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => {
                            let reply: &[u8] = if *kind == 0 { &reply_rmi } else { &reply_hmi };
                            conn.write_all(reply).unwrap();
                        }
                        Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                        Err(e) => panic!("device read: {e}"),
                    }
                }
            }
        }
    }

    fn courier(device: Arc<Device>, ready: mpsc::Sender<Arc<Courier>>) {
        let courier = Arc::new(Courier {
            jobs: Mutex::default(),
            unparker: sched::current_unparker(),
        });
        ready.send(courier.clone()).unwrap();
        let status = [b's'; STMO_STATUS];
        let joints = [b'j'; HSPO_JOINTS];
        let variables = [b'v'; HSPO_VARIABLES];
        let frame = vec![b'f'; SEAM_FRAME];
        let broker = HSPO_BROKER;
        loop {
            let job = courier.jobs.lock().unwrap().pop_front();
            match job {
                Some(Job::Status(arm, to)) => {
                    device.stmo[arm].send_to(&status, to).unwrap();
                    device.counts.stmo_statuses.fetch_add(1, Ordering::Relaxed);
                }
                Some(Job::Hspo(arm)) => {
                    device.hspo[arm].send_to(&joints, broker).unwrap();
                    device.hspo[arm].send_to(&variables, broker).unwrap();
                    device.counts.hspo.fetch_add(2, Ordering::Relaxed);
                }
                Some(Job::Seam) => {
                    if let Some(c) = device.seam.lock().unwrap().as_mut() {
                        c.write_all(&frame).unwrap();
                    }
                }
                None => {
                    sched::park(None);
                }
            }
        }
    }

    fn stmo_runner(arm: usize, counts: Arc<Counts>) {
        use mio::net::UdpSocket;
        use mio::{Events, Interest, Poll, Token};
        let mut sock = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        sock.connect(stmo_addr(arm)).unwrap();
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut sock, Token(0), Interest::READABLE)
            .unwrap();
        let mut events = Events::with_capacity(8);
        let command = [b'c'; STMO_COMMAND];
        let mut buf = [0u8; 512];
        sock.send(&command).unwrap();
        loop {
            poll.poll(&mut events, None).unwrap();
            loop {
                match sock.recv(&mut buf) {
                    Ok(_) => {
                        let _ = (std::time::SystemTime::now(), Instant::now(), Instant::now());
                        sock.send(&command).unwrap();
                        let _ = (std::time::SystemTime::now(), Instant::now());
                        counts.stmo_commands.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("stmo recv: {e}"),
                }
            }
        }
    }

    fn mio_poll_loop(
        mut sock: mio::net::UdpSocket,
        timeout: Option<Duration>,
        mut on: impl FnMut(&mio::net::UdpSocket, usize),
    ) {
        use mio::{Events, Interest, Poll, Token};
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut sock, Token(0), Interest::READABLE)
            .unwrap();
        let mut events = Events::with_capacity(8);
        let mut buf = [0u8; 2048];
        loop {
            poll.poll(&mut events, timeout).unwrap();
            loop {
                match sock.recv(&mut buf) {
                    Ok(n) => on(&sock, n),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("recv: {e}"),
                }
            }
        }
    }

    fn hspo_server(sock: UdpSocket, counts: Arc<Counts>) {
        sock.set_nonblocking(true).unwrap();
        let sock = mio::net::UdpSocket::from_std(sock);
        mio_poll_loop(sock, Some(Duration::from_millis(100)), |_, _| {
            let _ = Instant::now();
            let _ = std::time::SystemTime::now();
            counts.hspo_received.fetch_add(1, Ordering::Relaxed);
        });
    }

    fn tcp_idle_runner(addr: SocketAddr, timeout: Duration, counts: Arc<Counts>) {
        use mio::net::TcpStream;
        use mio::{Events, Interest, Poll, Token};
        let std = std::net::TcpStream::connect(addr).unwrap();
        std.set_nonblocking(true).unwrap();
        std.set_nodelay(true).unwrap();
        let mut stream = TcpStream::from_std(std);
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut stream, Token(0), Interest::READABLE)
            .unwrap();
        let mut events = Events::with_capacity(8);
        let request = [b'q'; RMI_REQUEST];
        let mut buf = [0u8; 2048];
        stream.write_all(&request).unwrap();
        loop {
            poll.poll(&mut events, Some(timeout)).unwrap();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => return,
                    Ok(_) => {
                        counts.rmi.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("tcp read: {e}"),
                }
            }
        }
    }

    fn seam_worker(counts: Arc<Counts>) {
        use mio::net::TcpStream;
        use mio::{Events, Interest, Poll, Token};
        let std = std::net::TcpStream::connect(SEAM).unwrap();
        std.set_nonblocking(true).unwrap();
        std.set_nodelay(true).unwrap();
        let mut stream = TcpStream::from_std(std);
        let mut poll = Poll::new().unwrap();
        poll.registry()
            .register(&mut stream, Token(0), Interest::READABLE)
            .unwrap();
        let (tx, rx) = mpsc::channel::<usize>();
        let reader_counts = counts.clone();
        spawn("seam-tracker", move || {
            while let Ok(n) = rx.recv() {
                let _ = Instant::now();
                reader_counts
                    .seam_bytes
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        });
        let mut events = Events::with_capacity(8);
        let mut buf = vec![0u8; 64 * 1024];
        let mut pending = 0;
        loop {
            poll.poll(&mut events, Some(Duration::from_millis(50)))
                .unwrap();
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => return,
                    Ok(n) => {
                        let _ = std::time::SystemTime::now();
                        pending += n;
                        if pending >= SEAM_FRAME {
                            tx.send(pending).unwrap();
                            pending = 0;
                        }
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                    Err(e) => panic!("seam read: {e}"),
                }
            }
            let _ = Instant::now();
        }
    }

    fn gvcp_control(counts: Arc<Counts>) {
        let sock = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        sock.connect(GVCP).unwrap();
        let mut last = Instant::now();
        sock.send(&[b'g'; 12]).unwrap();
        mio_poll_loop(sock, Some(Duration::from_millis(10)), move |sock, _| {
            counts.gvcp.fetch_add(1, Ordering::Relaxed);
            if last.elapsed() >= Duration::from_secs(1) {
                last = Instant::now();
                sock.send(&[b'g'; 12]).unwrap();
            }
        });
    }

    fn arc_device(sock: UdpSocket) {
        let feedback = [b'a'; ARC_FEEDBACK];
        let mut buf = [0u8; 64];
        let (_, client) = sock.recv_from(&mut buf).unwrap();
        let start = Instant::now();
        let mut frame = 0u32;
        loop {
            frame += 1;
            let next = start + Duration::from_millis(4) * frame;
            if let Some(wait) = next.checked_duration_since(Instant::now()) {
                thread::sleep(wait);
            }
            sock.send_to(&feedback, client).unwrap();
        }
    }

    fn arc_worker(counts: Arc<Counts>) {
        let sock = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        sock.connect(ARC_DEVICE).unwrap();
        sock.send(b"hello").unwrap();
        let (tx, rx) = mpsc::channel::<()>();
        spawn("leal-arc-status", move || while rx.recv().is_ok() {});
        spawn("arclink-feed", || {
            loop {
                thread::sleep(Duration::from_millis(20));
            }
        });
        mio_poll_loop(sock, None, move |_, _| {
            let _ = std::time::SystemTime::now();
            counts.arc.fetch_add(1, Ordering::Relaxed);
            let _ = tx.send(());
        });
    }

    fn bus_emulator(sock: UdpSocket) {
        sock.set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let mut buf = [0u8; 256];
        loop {
            if let Ok((n, from)) = sock.recv_from(&mut buf) {
                sock.send_to(&buf[..n], from).unwrap();
            }
        }
    }

    fn bus_master(counts: Arc<Counts>) {
        let link = UdpSocket::bind("127.0.0.1:0").unwrap();
        link.connect(BUS_EMULATOR).unwrap();
        link.set_nonblocking(true).unwrap();
        #[cfg(unix)]
        let (wake_tx, wake_rx) = std::os::unix::net::UnixDatagram::pair().unwrap();
        #[cfg(windows)]
        let (wake_tx, wake_rx) = {
            let rx = UdpSocket::bind("127.0.0.1:0").unwrap();
            let tx = UdpSocket::bind("127.0.0.1:0").unwrap();
            tx.connect(rx.local_addr().unwrap()).unwrap();
            (tx, rx)
        };
        wake_rx.set_nonblocking(true).unwrap();
        spawn("fieldhand-io", move || {
            let frame = [b'b'; BUS_FRAME];
            let mut buf = [0u8; 256];
            loop {
                readable(&[raw(&link), raw(&wake_rx)], 20);
                while wake_rx.recv(&mut buf).is_ok() {
                    link.send(&frame).unwrap();
                }
                while link.recv(&mut buf).is_ok() {
                    counts.bus.fetch_add(1, Ordering::Relaxed);
                }
            }
        });
        let start = Instant::now();
        let mut cycle = 0u32;
        loop {
            cycle += 1;
            let _ = std::time::SystemTime::now();
            let next = start + Duration::from_millis(4) * cycle;
            if let Some(wait) = next.checked_duration_since(Instant::now()) {
                thread::sleep(wait);
            }
            wake_tx.send(&[1]).unwrap();
        }
    }

    fn idle_timer(period: Duration) {
        loop {
            thread::sleep(period);
        }
    }

    fn next_timestamp(after: Duration) -> Duration {
        let grid = |period: Duration| {
            let p = period.as_nanos();
            Duration::from_nanos(((after.as_nanos() / p + 1) * p) as u64)
        };
        grid(HSPO_PERIOD).min(grid(SEAM_PERIOD))
    }

    fn on(t: Duration, period: Duration, phase: Duration) -> bool {
        t.as_nanos() % period.as_nanos() == phase.as_nanos()
    }

    pub fn main() {
        let sim_secs: u64 = std::env::args()
            .skip(1)
            .find_map(|arg| arg.parse().ok())
            .unwrap_or(20);
        let sim = Sim::builder().seed(1).build();
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        exec.freeze();
        let setup = sim.busy("cell-setup");
        let counts = Arc::new(Counts::default());
        let (courier_tx, courier_rx) = mpsc::channel();
        let device = sim.run(|| {
            let device = Arc::new(Device {
                stmo: (0..ARMS)
                    .map(|arm| UdpSocket::bind(stmo_addr(arm)).unwrap())
                    .collect(),
                hspo: (0..ARMS)
                    .map(|arm| UdpSocket::bind(hspo_source(arm)).unwrap())
                    .collect(),
                seam: Mutex::default(),
                inbox: (0..ARMS).map(|_| Mutex::default()).collect(),
                counts: counts.clone(),
            });
            let rmi: Vec<_> = (0..ARMS)
                .map(|arm| TcpListener::bind(rmi_addr(arm)).unwrap())
                .collect();
            let hmi: Vec<_> = (0..ARMS)
                .map(|arm| TcpListener::bind(hmi_addr(arm)).unwrap())
                .collect();
            let seam = TcpListener::bind(SEAM).unwrap();
            let gvcp = UdpSocket::bind(GVCP).unwrap();
            let arc = UdpSocket::bind(ARC_DEVICE).unwrap();
            let bus = UdpSocket::bind(BUS_EMULATOR).unwrap();
            let broker = UdpSocket::bind(HSPO_BROKER).unwrap();
            let d = device.clone();
            spawn("devices", move || reactor(d, rmi, hmi, seam, gvcp));
            let d = device.clone();
            spawn("cell-tx", move || courier(d, courier_tx));
            spawn("arc-device", move || arc_device(arc));
            spawn("bus-emulator", move || bus_emulator(bus));
            let c = counts.clone();
            spawn("hspo-server", move || hspo_server(broker, c));
            for arm in 0..ARMS {
                let c = counts.clone();
                spawn("stmo-runner", move || stmo_runner(arm, c));
                let c = counts.clone();
                spawn("rmi-runner", move || {
                    tcp_idle_runner(rmi_addr(arm), Duration::from_millis(8), c)
                });
                let c = counts.clone();
                spawn("hmi-runner", move || {
                    tcp_idle_runner(hmi_addr(arm), Duration::from_millis(96), c)
                });
            }
            let c = counts.clone();
            spawn("wecat3d-worker", move || seam_worker(c));
            let c = counts.clone();
            spawn("telegenic-gvcp", move || gvcp_control(c));
            let c = counts.clone();
            spawn("arclink-worker", move || arc_worker(c));
            let c = counts.clone();
            spawn("fieldhand-cycle", move || bus_master(c));
            spawn("magnet-events", || idle_timer(Duration::from_millis(100)));
            device
        });
        let courier = courier_rx.recv().unwrap();
        drop(setup);

        let (activity_tx, activity_rx) = mpsc::sync_channel::<()>(1);
        let end = Duration::from_secs(sim_secs);
        let (mut checks, mut waits, mut jumps, mut entered) = (0u64, 0u64, 0u64, 0u64);
        let base = exec.now();
        let mut t = next_timestamp(Duration::ZERO);
        let started = Instant::now();
        while t <= end {
            loop {
                let q = exec.quiescence();
                checks += 1;
                if !q.quiescent {
                    while activity_rx.try_recv().is_ok() {}
                    let tx = activity_tx.clone();
                    exec.arm_notify(
                        q.epoch,
                        Arc::new(move || {
                            let _ = tx.try_send(());
                        }),
                    );
                    waits += 1;
                    assert!(
                        activity_rx.recv_timeout(Duration::from_secs(10)).is_ok()
                            || exec.quiescence().quiescent,
                        "the sim stayed busy for 10 s: {q:?}"
                    );
                    continue;
                }
                if let Some(d) = q.next_deadline.filter(|d| *d < base + t) {
                    if exec.jump_to(d).is_ok() {
                        jumps += 1;
                    }
                    continue;
                }
                if exec.enter_timestamp_checked(base + t).is_ok() {
                    break;
                }
            }
            entered += 1;
            for arm in 0..ARMS {
                let phase = if arm == 0 { Duration::ZERO } else { 4 * MS };
                if on(t, STMO_PERIOD, phase) {
                    let drained: Vec<_> = device.inbox[arm].lock().unwrap().drain(..).collect();
                    if let Some(&from) = drained.last() {
                        courier.post(Job::Status(arm, from));
                    }
                }
                if on(t, HSPO_PERIOD, Duration::ZERO) {
                    courier.post(Job::Hspo(arm));
                }
            }
            if on(t, SEAM_PERIOD, Duration::ZERO) {
                courier.post(Job::Seam);
            }
            exec.leave_timestamp(base + t);
            t = next_timestamp(t);
        }
        let wall = started.elapsed();
        let c = &counts;
        println!(
            "{sim_secs} s of sim time in {wall:.3?} of wall time: {:.2}x realtime, {:.1} us per timestamp",
            end.as_secs_f64() / wall.as_secs_f64(),
            wall.as_secs_f64() * 1e6 / entered as f64,
        );
        println!(
            "executive: {entered} timestamps, {checks} quiescence checks, {waits} activity waits, {jumps} jumps"
        );
        println!(
            "stmo statuses {} commands {}, hspo sent {} received {}, seam {} KiB, tcp replies {}, arc {}, bus {}, gvcp {}",
            c.stmo_statuses.load(Ordering::Relaxed),
            c.stmo_commands.load(Ordering::Relaxed),
            c.hspo.load(Ordering::Relaxed),
            c.hspo_received.load(Ordering::Relaxed),
            c.seam_bytes.load(Ordering::Relaxed) / 1024,
            c.rmi.load(Ordering::Relaxed),
            c.arc.load(Ordering::Relaxed),
            c.bus.load(Ordering::Relaxed),
            c.gvcp.load(Ordering::Relaxed),
        );
        std::process::exit(0);
    }
}

#[cfg(any(unix, windows))]
fn main() {
    cell::main();
}

#[cfg(not(any(unix, windows)))]
fn main() {}
