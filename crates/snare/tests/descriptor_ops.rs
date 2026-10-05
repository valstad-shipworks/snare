#![cfg(unix)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::time::Duration;

use snare::Sim;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn udp_replacement() -> (Vec<i32>, Vec<bool>, Vec<u8>) {
    let source = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").unwrap();
    let retained = target.try_clone().unwrap();
    let old_address = target.local_addr().unwrap();
    let fd = source.as_raw_fd();
    let targetfd = target.as_raw_fd();
    assert_eq!(
        unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    assert_eq!(unsafe { libc::dup2(fd, fd) }, fd);
    let unchanged = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert_eq!(unsafe { libc::dup2(-1, targetfd) }, -1);
    let invalid_source = errno();
    assert_eq!(target.local_addr().unwrap(), old_address);
    assert_eq!(unsafe { libc::dup2(fd, -1) }, -1);
    let invalid_target = errno();
    assert_eq!(unsafe { libc::dup2(fd, targetfd) }, targetfd);
    let duplicated_flags = unsafe { libc::fcntl(targetfd, libc::F_GETFD) };
    assert_eq!(target.local_addr().unwrap(), source.local_addr().unwrap());
    target.set_broadcast(true).unwrap();
    let shared = source.broadcast().unwrap();
    let old_held = UdpSocket::bind(old_address).is_err();
    drop(retained);
    let old_released = UdpSocket::bind(old_address).is_ok();
    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    sender
        .send_to(b"replacement", source.local_addr().unwrap())
        .unwrap();
    drop(source);
    target
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = [0; 32];
    let n = target.recv(&mut bytes).unwrap();
    (
        vec![unchanged, invalid_source, invalid_target, duplicated_flags],
        vec![shared, old_held, old_released],
        bytes[..n].to_vec(),
    )
}

#[test]
fn dup2_replacement_preserves_shared_state_and_releases_old_ownership_os_truth() {
    let real = udp_replacement();
    assert_eq!(
        real,
        (
            vec![libc::FD_CLOEXEC, libc::EBADF, libc::EBADF, 0],
            vec![true; 3],
            b"replacement".to_vec()
        )
    );
    assert_eq!(Sim::new().run(udp_replacement), real);
    #[cfg(target_os = "linux")]
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(udp_replacement),
        real
    );
}

#[cfg(target_os = "linux")]
#[test]
fn dup3_flags_errors_and_same_descriptor_os_truth() {
    let probe = || {
        let source = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let original_address = target.local_addr().unwrap();
        let fd = source.as_raw_fd();
        let targetfd = target.as_raw_fd();
        assert_eq!(unsafe { libc::dup3(fd, fd, 0) }, -1);
        let same = errno();
        assert_eq!(unsafe { libc::dup3(fd, targetfd, libc::O_NONBLOCK) }, -1);
        let invalid_flags = errno();
        assert_eq!(target.local_addr().unwrap(), original_address);
        assert_eq!(
            unsafe { libc::dup3(fd, targetfd, libc::O_CLOEXEC) },
            targetfd
        );
        assert_eq!(target.local_addr().unwrap(), source.local_addr().unwrap());
        let cloexec = unsafe { libc::fcntl(targetfd, libc::F_GETFD) };
        assert_eq!(unsafe { libc::dup3(fd, targetfd, 0) }, targetfd);
        let clear = unsafe { libc::fcntl(targetfd, libc::F_GETFD) };
        (same, invalid_flags, cloexec, clear)
    };
    let real = probe();
    assert_eq!(real, (libc::EINVAL, libc::EINVAL, libc::FD_CLOEXEC, 0));
    assert_eq!(Sim::new().run(probe), real);
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

fn real_file_replaces_socket() -> (bool, bool) {
    let source = snare_interpose::real(|| std::fs::File::open("/dev/null").unwrap());
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let target = socket.into_raw_fd();
    assert_eq!(unsafe { libc::dup2(source.as_raw_fd(), target) }, target);
    let mut replaced = unsafe { std::fs::File::from_raw_fd(target) };
    let n = replaced.read(&mut [0; 8]).unwrap();
    (n == 0, UdpSocket::bind(address).is_ok())
}

#[test]
fn real_file_replaces_simulated_socket_os_truth() {
    let real = real_file_replaces_socket();
    assert_eq!(real, (true, true));
    assert_eq!(Sim::new().run(real_file_replaces_socket), real);
    #[cfg(target_os = "linux")]
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(real_file_replaces_socket),
        real
    );
}

fn socket_replaces_real_file() -> Vec<u8> {
    let source = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = snare_interpose::real(|| std::fs::File::open("/dev/null").unwrap()).into_raw_fd();
    assert_eq!(unsafe { libc::dup2(source.as_raw_fd(), target) }, target);
    let duplicate = unsafe { UdpSocket::from_raw_fd(target) };
    let destination = UdpSocket::bind("127.0.0.1:0").unwrap();
    duplicate
        .send_to(b"socket replaces file", destination.local_addr().unwrap())
        .unwrap();
    destination
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut bytes = [0; 32];
    let n = destination.recv(&mut bytes).unwrap();
    bytes[..n].to_vec()
}

#[test]
fn simulated_socket_replaces_real_file_os_truth() {
    let real = socket_replaces_real_file();
    assert_eq!(real, b"socket replaces file");
    assert_eq!(Sim::new().run(socket_replaces_real_file), real);
    #[cfg(target_os = "linux")]
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(socket_replaces_real_file),
        real
    );
}

fn tcp_and_udp_replace_each_other() -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let old_address = udp.local_addr().unwrap();
    let target = udp.into_raw_fd();
    assert_eq!(unsafe { libc::dup2(client.as_raw_fd(), target) }, target);
    let mut duplicate = unsafe { TcpStream::from_raw_fd(target) };
    assert!(UdpSocket::bind(old_address).is_ok());
    drop(client);
    duplicate.write_all(b"tcp replacement").unwrap();
    let mut bytes = [0; 15];
    server.read_exact(&mut bytes).unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let target = duplicate.into_raw_fd();
    assert_eq!(unsafe { libc::dup2(udp.as_raw_fd(), target) }, target);
    let duplicate = unsafe { UdpSocket::from_raw_fd(target) };
    assert_eq!(duplicate.local_addr().unwrap(), udp.local_addr().unwrap());
    server
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert_eq!(server.read(&mut [0; 8]).unwrap(), 0);
    bytes.to_vec()
}

#[test]
fn sockets_replace_other_backend_socket_ownership_os_truth() {
    let real = tcp_and_udp_replace_each_other();
    assert_eq!(real, b"tcp replacement");
    assert_eq!(Sim::new().run(tcp_and_udp_replace_each_other), real);
    #[cfg(target_os = "linux")]
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(tcp_and_udp_replace_each_other),
        real
    );
}

#[cfg(target_os = "linux")]
#[test]
fn event_and_epoll_descriptor_flags_and_replacement_os_truth() {
    let probe = || {
        let eventfd = unsafe { libc::eventfd(3, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        assert!(eventfd >= 0);
        let event = unsafe { std::fs::File::from_raw_fd(eventfd) };
        let event_copy = event.try_clone().unwrap();
        let epollfd = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
        assert!(epollfd >= 0);
        let epoll = unsafe { std::fs::File::from_raw_fd(epollfd) };
        let epoll_copy = epoll.try_clone().unwrap();
        let initial = [
            eventfd,
            event_copy.as_raw_fd(),
            epollfd,
            epoll_copy.as_raw_fd(),
        ]
        .map(|fd| unsafe { libc::fcntl(fd, libc::F_GETFD) });
        assert_eq!(unsafe { libc::eventfd(0, -1) }, -1);
        let invalid_event_flags = errno();
        assert_eq!(unsafe { libc::epoll_create1(-1) }, -1);
        let invalid_epoll_flags = errno();
        assert_eq!(unsafe { libc::dup2(eventfd, epollfd) }, epollfd);
        let changed = unsafe { libc::fcntl(epollfd, libc::F_GETFD) };
        let mut counter = 0u64;
        assert_eq!(
            unsafe { libc::read(epollfd, (&mut counter as *mut u64).cast(), 8) },
            8
        );
        assert_eq!(
            unsafe { libc::read(event_copy.as_raw_fd(), (&mut counter as *mut u64).cast(), 8) },
            -1
        );
        let shared_consumption = errno();
        let mut out = unsafe { std::mem::zeroed::<libc::epoll_event>() };
        let remaining_epoll = unsafe { libc::epoll_wait(epoll_copy.as_raw_fd(), &mut out, 1, 0) };
        (
            initial,
            invalid_event_flags,
            invalid_epoll_flags,
            changed,
            counter,
            shared_consumption,
            remaining_epoll,
        )
    };
    let real = probe();
    assert_eq!(
        real,
        (
            [libc::FD_CLOEXEC; 4],
            libc::EINVAL,
            libc::EINVAL,
            0,
            3,
            libc::EAGAIN,
            0
        )
    );
    assert_eq!(Sim::new().run(probe), real);
}

#[test]
fn replacement_keeps_socket_history_attached_to_its_open_description() {
    let probe = || {
        let source = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source_id = snare::socket_id(&source).unwrap();
        let old_target_id = snare::socket_id(&target).unwrap();
        assert_eq!(
            unsafe { libc::dup2(source.as_raw_fd(), target.as_raw_fd()) },
            target.as_raw_fd()
        );
        assert_eq!(snare::socket_id(&target), Some(source_id));
        assert!(
            snare::socket_entry(old_target_id)
                .unwrap()
                .closed_at
                .is_some()
        );
        drop(source);
        assert!(snare::socket_entry(source_id).unwrap().closed_at.is_none());
        drop(target);
        assert!(snare::socket_entry(source_id).unwrap().closed_at.is_some());
    };
    Sim::new().run(probe);
    #[cfg(target_os = "linux")]
    Sim::builder()
        .host(snare::HostProfile::new().build())
        .build()
        .run(probe);
}

#[test]
fn replacement_releases_virtual_file_ownership_and_persists_last_close() {
    use snare::FsBuilder;
    let fs = FsBuilder::new()
        .own_prefix("/descriptor-test")
        .dir("/descriptor-test")
        .build();
    Sim::builder().fs(fs).build().run(|| {
        let mut old_file = std::fs::File::create("/descriptor-test/replaced").unwrap();
        old_file.write_all(b"persist on replacement").unwrap();
        let fd = old_file.into_raw_fd();
        let source = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(unsafe { libc::dup2(source.as_raw_fd(), fd) }, fd);
        let target = unsafe { UdpSocket::from_raw_fd(fd) };
        assert_eq!(target.local_addr().unwrap(), source.local_addr().unwrap());
        assert_eq!(
            std::fs::read("/descriptor-test/replaced").unwrap(),
            b"persist on replacement"
        );
        let file = std::fs::File::open("/descriptor-test/replaced").unwrap();
        let address = target.local_addr().unwrap();
        drop(source);
        let fd = target.into_raw_fd();
        assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), fd) }, fd);
        let mut duplicate = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut bytes = Vec::new();
        duplicate.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"persist on replacement");
        assert!(UdpSocket::bind(address).is_ok());
    });
}

#[test]
fn unsupported_fcntl_command_reports_the_host_error_os_truth() {
    let probe = || {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(unsafe { libc::fcntl(socket.as_raw_fd(), -1, 0) }, -1);
        errno()
    };
    let real = probe();
    assert_eq!(real, libc::EINVAL);
    assert_eq!(Sim::new().run(probe), real);
    #[cfg(target_os = "linux")]
    assert_eq!(
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(probe),
        real
    );
}

fn concurrent_replacement_and_close(real_target: bool) {
    use std::sync::{Arc, Barrier};
    for _ in 0..64 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let source = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (mut peer, _) = listener.accept().unwrap();
        let targetfd = if real_target {
            let file = snare_interpose::real(|| std::fs::File::open("/dev/null").unwrap());
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD, 128) }
        } else {
            let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
            unsafe { libc::fcntl(udp.as_raw_fd(), libc::F_DUPFD, 128) }
        };
        assert!(targetfd >= 128);
        let fd = source.as_raw_fd();
        let source_id = snare::socket_id(&source);
        let gate = Arc::new(Barrier::new(3));
        let replacing_gate = gate.clone();
        let replacing = std::thread::spawn(move || {
            replacing_gate.wait();
            assert_eq!(unsafe { libc::dup2(fd, targetfd) }, targetfd);
        });
        let closing_gate = gate.clone();
        let closing = std::thread::spawn(move || {
            closing_gate.wait();
            let result = unsafe { libc::close(targetfd) };
            assert!(result == 0 || result == -1 && errno() == libc::EBADF);
        });
        gate.wait();
        replacing.join().unwrap();
        closing.join().unwrap();
        let open = snare_interpose::real(|| unsafe { libc::fcntl(targetfd, libc::F_GETFD) }) >= 0;
        drop(source);
        if let Some(source_id) = source_id {
            assert_eq!(
                snare::socket_entry(source_id).unwrap().closed_at.is_none(),
                open
            );
        }
        peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        if open {
            let mut alias = unsafe { TcpStream::from_raw_fd(targetfd) };
            alias.write_all(b"after the race").unwrap();
            let mut bytes = [0; 14];
            peer.read_exact(&mut bytes).unwrap();
            assert_eq!(&bytes, b"after the race");
            drop(alias);
        }
        assert_eq!(peer.read(&mut [0; 8]).unwrap(), 0);
        if let Some(source_id) = source_id {
            assert!(snare::socket_entry(source_id).unwrap().closed_at.is_some());
        }
    }
}

#[test]
fn concurrent_close_and_cross_backend_replacement_preserve_ownership_os_truth() {
    for real_target in [false, true] {
        concurrent_replacement_and_close(real_target);
        Sim::new().run(|| concurrent_replacement_and_close(real_target));
        #[cfg(target_os = "linux")]
        Sim::builder()
            .host(snare::HostProfile::new().build())
            .build()
            .run(|| concurrent_replacement_and_close(real_target));
    }
}

#[test]
fn a_linger_wait_allows_other_descriptor_operations() {
    let nic = snare::NicSpec::new("linger-test")
        .index(4)
        .address("10.0.0.1/24".parse::<snare::IpNet>().unwrap())
        .station("10.0.0.2".parse::<std::net::IpAddr>().unwrap())
        .policy(snare::NicPolicy {
            latency: Duration::from_millis(100),
            ..Default::default()
        });
    Sim::builder().nic(nic).build().run(|| {
        let listener = TcpListener::bind("10.0.0.2:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: if cfg!(target_os = "macos") { 100 } else { 1 },
        };
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    client.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    size_of::<libc::linger>() as u32,
                )
            },
            0
        );
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        let other_gate = gate.clone();
        let (start_tx, start_rx) = std::sync::mpsc::channel();
        let other = std::thread::spawn(move || {
            other_gate.wait();
            let start: std::time::Instant = start_rx.recv().unwrap();
            std::thread::sleep(Duration::from_millis(10));
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            drop(socket.try_clone().unwrap());
            drop(socket);
            start.elapsed()
        });
        gate.wait();
        let start = std::time::Instant::now();
        client.write_all(b"in flight").unwrap();
        start_tx.send(start).unwrap();
        drop(client);
        let elapsed = start.elapsed();
        let other_completed = other.join().unwrap();
        assert!(
            elapsed >= Duration::from_millis(100),
            "linger ended after {elapsed:?}; helper finished at {other_completed:?}"
        );
        assert!(other_completed >= Duration::from_millis(10));
        assert!(other_completed < Duration::from_millis(100));
    });
}

#[test]
fn replacing_a_real_linger_socket_preserves_the_simulated_description() {
    Sim::new().run(|| {
        let (real_client, _real_server) = snare_interpose::real(|| {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let server = listener.accept().unwrap().0;
            (client, server)
        });
        let linger = libc::linger {
            l_onoff: 1,
            l_linger: if cfg!(target_os = "macos") { 100 } else { 1 },
        };
        assert_eq!(
            snare_interpose::real(|| unsafe {
                libc::setsockopt(
                    real_client.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&linger as *const libc::linger).cast(),
                    size_of::<libc::linger>() as u32,
                )
            }),
            0
        );
        let source = UdpSocket::bind("127.0.0.1:0").unwrap();
        assert_eq!(
            unsafe { libc::dup2(source.as_raw_fd(), real_client.as_raw_fd()) },
            real_client.as_raw_fd()
        );
        assert_eq!(snare::socket_id(&real_client), snare::socket_id(&source));
        assert_eq!(
            real_client.local_addr().unwrap(),
            source.local_addr().unwrap()
        );
        let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
        source.connect(sink.local_addr().unwrap()).unwrap();
        source.send(b"first").unwrap();
        assert_eq!(
            unsafe { libc::write(real_client.as_raw_fd(), b"second".as_ptr().cast(), 6) },
            6
        );
        let mut bytes = [0; 16];
        let length = sink.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..length], b"first");
        let length = sink.recv(&mut bytes).unwrap();
        assert_eq!(&bytes[..length], b"second");
    });
}
