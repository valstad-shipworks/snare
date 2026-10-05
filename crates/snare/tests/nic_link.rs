//! Link state: carrier and admin flaps, what they do to datagrams and TCP bytes crossing the link,
//! scheduled transitions on the sim's clock, and what the log records.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use snare::{
    Fault, IpNet, NicSpec, RecordedEvent, Sim, nic_counters, schedule_link, set_link,
    set_nic_policy,
};

#[cfg(unix)]
mod code {
    pub const ENETUNREACH: i32 = libc::ENETUNREACH;
    #[cfg(target_os = "macos")]
    pub const ENETDOWN: i32 = libc::ENETDOWN;
}

#[cfg(windows)]
mod code {
    pub const ENETUNREACH: i32 = 10051;
    pub const EADDRNOTAVAIL: i32 = 10049;
}

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn eth0() -> NicSpec {
    NicSpec::new("eth0")
        .index(4)
        .address(net("10.0.0.1/24"))
        .station(ip("10.0.0.2"))
}

fn sim() -> Sim {
    Sim::builder().nic(eth0()).build()
}

fn try_recv(sock: &UdpSocket) -> Option<Vec<u8>> {
    sock.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 64];
    match sock.recv_from(&mut buf) {
        Ok((n, _)) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(e) => panic!("recv failed: {e}"),
    }
}

fn try_read(stream: &mut TcpStream) -> Option<Vec<u8>> {
    stream.set_nonblocking(true).unwrap();
    let mut buf = [0u8; 64];
    match stream.read(&mut buf) {
        Ok(n) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == ErrorKind::WouldBlock => None,
        Err(e) => panic!("read failed: {e}"),
    }
}

/// A connection from the host to a station listener across eth0: (client, accepted).
fn tcp_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("10.0.0.2:9400").unwrap();
    let client = TcpStream::connect("10.0.0.2:9400").unwrap();
    let (server, _) = listener.accept().unwrap();
    (client, server)
}

#[test]
fn carrier_down_send_succeeds_frame_lost() {
    sim().run(|| {
        let station = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let sock = UdpSocket::bind("10.0.0.1:0").unwrap();
        set_link("eth0", false).unwrap();
        let sent = sock.send_to(b"lost", "10.0.0.2:7000");
        if cfg!(windows) {
            // Media sense withdraws the interface's routes with its carrier.
            assert_eq!(sent.unwrap_err().raw_os_error(), Some(code::ENETUNREACH));
        } else {
            sent.unwrap();
            let counters = nic_counters("eth0").unwrap();
            assert_eq!((counters.tx_dropped, counters.tx_carrier_errors), (1, 1));
            assert_eq!(counters.tx_packets, 0);
        }
        assert!(try_recv(&station).is_none());
        set_link("eth0", true).unwrap();
        sock.send_to(b"back", "10.0.0.2:7000").unwrap();
        assert_eq!(try_recv(&station).unwrap(), b"back");
        let counters = nic_counters("eth0").unwrap();
        assert_eq!((counters.tx_packets, counters.tx_bytes), (1, 4 + 42));
    });
}

/// An interface taken administratively down: Linux reports `ENETUNREACH` for both sends, macOS
/// `ENETDOWN` for the bound one, and both keep the address bindable. Windows treats a disabled
/// adapter as it treats a lost carrier, withdrawing its routes and addresses
/// ([Microsoft Learn: Disable Media Sensing feature for TCP/IP](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/disable-media-sensing-feature-for-tcpip)):
/// both sends fail `WSAENETUNREACH` and the address no longer binds (`WSAEADDRNOTAVAIL`).
#[test]
fn admin_down_errnos() {
    let sim = sim();
    sim.set_default_route(None).unwrap();
    sim.run(|| {
        let bound = UdpSocket::bind("10.0.0.1:0").unwrap();
        let wildcard = UdpSocket::bind("0.0.0.0:0").unwrap();
        snare::set_nic("eth0", |spec| spec.admin_up = false).unwrap();
        let bound_err = bound.send_to(b"x", "10.0.0.2:7000").unwrap_err();
        let wildcard_err = wildcard.send_to(b"x", "10.0.0.2:7000").unwrap_err();
        let bind = UdpSocket::bind("10.0.0.1:0");
        #[cfg(target_os = "linux")]
        {
            assert_eq!(bound_err.raw_os_error(), Some(code::ENETUNREACH));
            assert_eq!(wildcard_err.raw_os_error(), Some(code::ENETUNREACH));
            bind.unwrap();
        }
        #[cfg(target_os = "macos")]
        {
            assert_eq!(bound_err.raw_os_error(), Some(code::ENETDOWN));
            assert_eq!(wildcard_err.raw_os_error(), Some(code::ENETUNREACH));
            bind.unwrap();
        }
        #[cfg(windows)]
        {
            assert_eq!(bound_err.raw_os_error(), Some(code::ENETUNREACH));
            assert_eq!(wildcard_err.raw_os_error(), Some(code::ENETUNREACH));
            assert_eq!(bind.unwrap_err().raw_os_error(), Some(code::EADDRNOTAVAIL));
        }
        snare::set_nic("eth0", |spec| spec.admin_up = true).unwrap();
        bound.send_to(b"x", "10.0.0.2:7000").unwrap();
    });
}

#[test]
fn inbound_lost_while_down_resumes_after() {
    sim().run(|| {
        let host = UdpSocket::bind("10.0.0.1:7100").unwrap();
        let station = UdpSocket::bind("10.0.0.2:0").unwrap();
        set_link("eth0", false).unwrap();
        station.send_to(b"lost", "10.0.0.1:7100").unwrap();
        assert!(try_recv(&host).is_none());
        assert_eq!(nic_counters("eth0").unwrap().rx_dropped, 1);
        set_link("eth0", true).unwrap();
        station.send_to(b"seen", "10.0.0.1:7100").unwrap();
        assert_eq!(try_recv(&host).unwrap(), b"seen");
        assert_eq!(nic_counters("eth0").unwrap().rx_packets, 1);
    });
}

#[test]
fn in_flight_datagram_discarded_by_flap() {
    sim().run(|| {
        set_nic_policy("eth0", |p| p.latency = Duration::from_millis(10)).unwrap();
        let host = UdpSocket::bind("10.0.0.1:7200").unwrap();
        let station = UdpSocket::bind("10.0.0.2:0").unwrap();
        station.send_to(b"flapped", "10.0.0.1:7200").unwrap();
        std::thread::sleep(Duration::from_millis(2));
        set_link("eth0", false).unwrap();
        set_link("eth0", true).unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert!(try_recv(&host).is_none(), "in flight across the flap");
        station.send_to(b"after", "10.0.0.1:7200").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(try_recv(&host).unwrap(), b"after");
        station.send_to(b"landed", "10.0.0.1:7200").unwrap();
        std::thread::sleep(Duration::from_millis(20));
        set_link("eth0", false).unwrap();
        set_link("eth0", true).unwrap();
        assert_eq!(
            try_recv(&host).unwrap(),
            b"landed",
            "arrived before the flap"
        );
    });
}

#[test]
fn tcp_stalls_and_resumes_in_order() {
    sim().run(|| {
        let (mut client, mut server) = tcp_pair();
        client.write_all(b"ab").unwrap();
        assert_eq!(try_read(&mut server).unwrap(), b"ab");
        set_link("eth0", false).unwrap();
        client.write_all(b"cd").unwrap();
        client.write_all(b"ef").unwrap();
        assert!(try_read(&mut server).is_none(), "stalled on the link");
        set_link("eth0", true).unwrap();
        assert_eq!(try_read(&mut server).unwrap(), b"cdef");
        set_link("eth0", false).unwrap();
        client.write_all(b"gh").unwrap();
        assert!(try_read(&mut server).is_none());
        snare::remove_nic("eth0").unwrap();
        assert_eq!(try_read(&mut server).unwrap(), b"gh");
    });
}

#[test]
fn blocked_reader_wakes_on_scheduled_link_up() {
    let started = Instant::now();
    let waited = sim().run(|| {
        let (mut client, mut server) = tcp_pair();
        set_link("eth0", false).unwrap();
        client.write_all(b"late").unwrap();
        schedule_link("eth0", Duration::from_secs(10), true).unwrap();
        let t0 = Instant::now();
        let mut buf = [0u8; 8];
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"late");
        t0.elapsed()
    });
    assert!(waited >= Duration::from_secs(10), "virtual wait {waited:?}");
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "real time {:?}",
        started.elapsed()
    );
}

#[test]
fn blocked_reader_gives_up_when_link_never_returns() {
    sim().run(|| {
        let (mut client, mut server) = tcp_pair();
        set_link("eth0", false).unwrap();
        client.write_all(b"never").unwrap();
        let mut buf = [0u8; 8];
        let err = server.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::WouldBlock);
    });
}

#[test]
fn wall_clock_scheduled_link_uses_real_waker() {
    let sim = Sim::builder().wall_clock().nic(eth0()).build();
    let started = snare::real(Instant::now);
    sim.run(|| {
        let (mut client, mut server) = tcp_pair();
        set_link("eth0", false).unwrap();
        client.write_all(b"real").unwrap();
        schedule_link("eth0", Duration::from_millis(30), true).unwrap();
        let mut buf = [0u8; 8];
        let n = server.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"real");
    });
    if cfg!(unix) {
        assert!(snare::real(|| started.elapsed()) >= Duration::from_millis(30));
    }
}

#[test]
fn link_changes_are_recorded() {
    let sim = sim();
    sim.run(|| {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        set_link("eth0", false).unwrap();
        let _ = sock.send_to(b"x", "10.0.0.2:7000");
        schedule_link("eth0", Duration::from_millis(5), true).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        assert!(snare::nic("eth0").unwrap().spec.carrier);
    });
    let entries = sim.recorded_events();
    let events: Vec<_> = entries.iter().map(|e| e.event.clone()).collect();
    let changed = |carrier| RecordedEvent::NicChanged {
        nic: "eth0".into(),
        admin_up: true,
        carrier,
    };
    let down = events
        .iter()
        .position(|e| *e == changed(false))
        .expect("down");
    let up = events.iter().position(|e| *e == changed(true)).expect("up");
    assert!(down < up);
    let gap = entries[up].at - entries[down].at;
    assert!(
        gap >= Duration::from_millis(5) && gap < Duration::from_millis(10),
        "the scheduled change is stamped when it fell due, not when seen: {gap:?}"
    );
    if cfg!(unix) {
        let dropped = events.iter().position(|e| {
            matches!(e, RecordedEvent::Fault { addr: Some(a), fault: Fault::LinkDown { nic } }
                if nic == "eth0" && *a == "10.0.0.2:7000".parse::<SocketAddr>().unwrap())
        });
        assert!(dropped.is_some_and(|d| down < d && d < up), "{events:?}");
    }
}

#[cfg(target_os = "linux")]
mod raw {
    pub fn open_on(index: i32) -> i32 {
        unsafe {
            let fd = libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK,
                i32::from(0x88A4u16.to_be()),
            );
            assert!(fd >= 0);
            let mut sll: libc::sockaddr_ll = std::mem::zeroed();
            sll.sll_family = libc::AF_PACKET as u16;
            sll.sll_ifindex = index;
            let rc = libc::bind(
                fd,
                (&sll as *const libc::sockaddr_ll).cast(),
                size_of::<libc::sockaddr_ll>() as u32,
            );
            assert_eq!(rc, 0);
            fd
        }
    }

    pub fn read(fd: i32) -> isize {
        let mut buf = [0u8; 2048];
        unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
    }
}

#[cfg(target_os = "macos")]
mod raw {
    const BIOCSETIF: libc::c_ulong = 0x8020_426c;

    pub fn open_on(_index: i32) -> i32 {
        let path = std::ffi::CString::new("/dev/bpf0").unwrap();
        let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK) };
        assert!(fd >= 0);
        let mut ifr = [0u8; 32];
        ifr[..4].copy_from_slice(b"eth0");
        assert_eq!(unsafe { libc::ioctl(fd, BIOCSETIF, ifr.as_mut_ptr()) }, 0);
        fd
    }

    pub fn read(fd: i32) -> isize {
        let mut buf = [0u8; 4096];
        unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn raw_l2_frames_respect_link() {
    sim().run(|| {
        let a = raw::open_on(4);
        let b = raw::open_on(4);
        let frame = [0u8; 60];
        let write = |len: usize| unsafe { libc::write(a, frame.as_ptr().cast(), len) };
        assert_eq!(write(60), 60);
        assert_eq!(
            raw::read(b),
            60 + if cfg!(target_os = "macos") { 18 } else { 0 }
        );
        set_link("eth0", false).unwrap();
        assert_eq!(write(60), 60, "the send succeeds");
        assert_eq!(raw::read(b), -1, "the frame never arrives");
        assert_eq!(nic_counters("eth0").unwrap().tx_carrier_errors, 1);
        set_link("eth0", true).unwrap();
        let big = vec![0u8; 1600];
        let rc = unsafe { libc::write(a, big.as_ptr().cast(), big.len()) };
        assert_eq!(rc, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EMSGSIZE)
        );
        if cfg!(target_os = "linux") {
            snare::set_nic("eth0", |spec| spec.admin_up = false).unwrap();
            assert_eq!(write(60), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ENETDOWN)
            );
        }
        unsafe {
            libc::close(a);
            libc::close(b);
        }
    });
}
