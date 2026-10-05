#![cfg(unix)]

use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use snare::sched::{Executive, ExecutiveConfig};

fn settle(exec: &Executive) {
    let start = snare::real(Instant::now);
    loop {
        let state = exec.quiescence();
        if state.quiescent && state.blocked == 1 {
            return;
        }
        assert!(
            snare::real(|| start.elapsed()) < Duration::from_secs(2),
            "{state:?}"
        );
        snare::real(std::thread::yield_now);
    }
}

#[cfg(target_os = "linux")]
fn host_descriptor_change(replace: bool) {
    let sim = snare::Sim::builder()
        .host(snare::HostProfile::new().build())
        .build();
    sim.pause_time();
    sim.run(|| {
        snare::sched::mark_driver_thread();
        let exec = snare::sched::attach(ExecutiveConfig::default()).unwrap();
        let target = UdpSocket::bind("127.0.0.1:0").unwrap();
        let source = UdpSocket::bind("127.0.0.1:0").unwrap();
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .send_to(b"ready", source.local_addr().unwrap())
            .unwrap();
        let fd = target.as_raw_fd();
        let finished = Arc::new(AtomicBool::new(false));
        let completion = finished.clone();
        let waiter = std::thread::spawn(move || {
            let mut pollfd = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { libc::poll(&mut pollfd, 1, 1000) };
            completion.store(true, Ordering::Release);
            (result, pollfd.revents)
        });
        settle(&exec);
        if replace {
            assert_eq!(unsafe { libc::dup2(source.as_raw_fd(), fd) }, fd);
        } else {
            drop(target);
        }
        let observed = !exec.quiescence().quiescent || finished.load(Ordering::Acquire);
        exec.enter_timestamp(Duration::from_secs(1));
        exec.leave_timestamp(Duration::from_secs(1));
        let result = waiter.join().unwrap();
        assert_eq!(
            result,
            (
                1,
                if replace {
                    libc::POLLIN
                } else {
                    libc::POLLNVAL
                }
            )
        );
        assert!(
            observed,
            "descriptor mutation left its readiness waiter quiescent"
        );
    });
}

#[cfg(target_os = "linux")]
#[test]
fn host_close_releases_the_model_poll_waiter() {
    host_descriptor_change(false);
}

#[cfg(target_os = "linux")]
#[test]
fn host_dup2_replacement_releases_the_model_poll_waiter() {
    host_descriptor_change(true);
}

#[cfg(target_os = "linux")]
fn netlink_socket() -> libc::c_int {
    let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
    assert!(fd >= 0);
    fd
}

#[cfg(target_os = "linux")]
fn netlink_request(fd: libc::c_int, method: u8) {
    let mut request = [0u8; 32];
    request[..4].copy_from_slice(&32u32.to_ne_bytes());
    request[4..6].copy_from_slice(&18u16.to_ne_bytes());
    request[6..8].copy_from_slice(&0x301u16.to_ne_bytes());
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    let mut destination: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    destination.nl_family = libc::AF_NETLINK as _;
    let sent = match method {
        0 => unsafe { libc::send(fd, request.as_ptr().cast(), request.len(), 0) },
        1 => unsafe {
            libc::sendto(
                fd,
                request.as_ptr().cast(),
                request.len(),
                0,
                std::ptr::from_ref(&destination).cast(),
                std::mem::size_of_val(&destination) as _,
            )
        },
        2 => {
            let mut iov = libc::iovec {
                iov_base: request.as_mut_ptr().cast(),
                iov_len: request.len(),
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = std::ptr::from_mut(&mut destination).cast();
            msg.msg_namelen = std::mem::size_of_val(&destination) as _;
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            unsafe { libc::sendmsg(fd, &msg, 0) }
        }
        _ => unreachable!(),
    };
    assert_eq!(
        sent,
        32,
        "method {method}: {}",
        std::io::Error::last_os_error()
    );
}

#[cfg(target_os = "linux")]
fn empty_netlink_readiness() -> [(libc::c_int, i16); 2] {
    let fd = netlink_socket();
    let result = [libc::POLLIN, libc::POLLOUT].map(|events| {
        let mut pollfd = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
        (result, pollfd.revents)
    });
    assert_eq!(unsafe { libc::close(fd) }, 0);
    result
}

#[cfg(target_os = "linux")]
#[test]
fn empty_host_netlink_poll_matches_the_native_socket() {
    let expected = empty_netlink_readiness();
    assert_eq!(expected, [(0, 0), (1, libc::POLLOUT)]);
    for deterministic in [false, true] {
        let mut builder = snare::Sim::builder().host(snare::HostProfile::new().build());
        if deterministic {
            builder = builder.deterministic();
        }
        assert_eq!(builder.build().run(empty_netlink_readiness), expected);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn host_netlink_requests_release_the_model_poll_waiter() {
    for method in 0..3 {
        let native = netlink_socket();
        netlink_request(native, method);
        let mut pollfd = libc::pollfd {
            fd: native,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut pollfd, 1, 1000) }, 1);
        assert_eq!(pollfd.revents, libc::POLLIN);
        assert_eq!(unsafe { libc::close(native) }, 0);

        let sim = snare::Sim::builder()
            .host(snare::HostProfile::new().build())
            .build();
        sim.pause_time();
        sim.run(|| {
            snare::sched::mark_driver_thread();
            let exec = snare::sched::attach(ExecutiveConfig::default()).unwrap();
            let fd = netlink_socket();
            let finished = Arc::new(AtomicBool::new(false));
            let completion = finished.clone();
            let waiter = std::thread::spawn(move || {
                let mut pollfd = libc::pollfd {
                    fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                let result = unsafe { libc::poll(&mut pollfd, 1, 1000) };
                completion.store(true, Ordering::Release);
                (result, pollfd.revents)
            });
            settle(&exec);
            netlink_request(fd, method);
            let observed = !exec.quiescence().quiescent || finished.load(Ordering::Acquire);
            exec.enter_timestamp(Duration::from_secs(1));
            exec.leave_timestamp(Duration::from_secs(1));
            let result = waiter.join().unwrap();
            assert_eq!(unsafe { libc::close(fd) }, 0);
            assert_eq!(result, (1, libc::POLLIN));
            assert!(
                observed,
                "netlink reply left its readiness waiter quiescent"
            );
        });
    }
}

#[cfg(target_os = "linux")]
fn netlink_edge_sequence() -> Vec<(libc::c_int, u32)> {
    let fd = netlink_socket();
    let alias = unsafe { libc::dup(fd) };
    assert!(alias >= 0);
    let epfd = unsafe { libc::epoll_create1(0) };
    assert!(epfd >= 0);
    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLET) as _,
        u64: 73,
    };
    assert_eq!(
        unsafe { libc::epoll_ctl(epfd, libc::EPOLL_CTL_ADD, fd, &mut event) },
        0
    );
    assert_eq!(unsafe { libc::close(fd) }, 0);
    let wait = || {
        let mut event = libc::epoll_event { events: 0, u64: 0 };
        let count = unsafe { libc::epoll_wait(epfd, &mut event, 1, 0) };
        if count == 1 {
            let token = event.u64;
            assert_eq!(token, 73);
        }
        (count, event.events)
    };
    let mut sequence = vec![wait()];
    netlink_request(alias, 1);
    sequence.push(wait());
    sequence.push(wait());
    netlink_request(alias, 2);
    sequence.push(wait());
    sequence.push(wait());
    let mut buffer = [0u8; 65536];
    loop {
        let n = unsafe {
            libc::recv(
                alias,
                buffer.as_mut_ptr().cast(),
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EAGAIN)
            );
            break;
        }
        assert!(n > 0);
    }
    sequence.push(wait());
    netlink_request(alias, 0);
    sequence.push(wait());
    assert_eq!(unsafe { libc::close(alias) }, 0);
    assert_eq!(unsafe { libc::close(epfd) }, 0);
    sequence
}

#[cfg(target_os = "linux")]
#[test]
fn host_netlink_aliases_and_new_response_edges_match_native_epoll() {
    let expected = netlink_edge_sequence();
    let edge = (1, libc::EPOLLIN as u32);
    assert_eq!(expected, [(0, 0), edge, (0, 0), edge, (0, 0), (0, 0), edge]);
    for deterministic in [false, true] {
        let mut builder = snare::Sim::builder().host(snare::HostProfile::new().build());
        if deterministic {
            builder = builder.deterministic();
        }
        assert_eq!(builder.build().run(netlink_edge_sequence), expected);
    }
}

#[cfg(target_os = "macos")]
fn kqueue_registration_change(enable: bool, modeled: bool) -> (bool, bool) {
    let exec = modeled.then(|| {
        snare::sched::mark_driver_thread();
        snare::sched::attach(ExecutiveConfig::default()).unwrap()
    });
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .send_to(b"ready", socket.local_addr().unwrap())
        .unwrap();
    let fd = socket.as_raw_fd();
    let kq = unsafe { libc::kqueue() };
    assert!(kq >= 0);
    let mut change = libc::kevent {
        ident: fd as _,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | if enable { libc::EV_DISABLE } else { 0 },
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    if enable {
        assert_eq!(
            unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) },
            0
        );
        change.flags = libc::EV_ENABLE;
    }
    let finished = Arc::new(AtomicBool::new(false));
    let completion = finished.clone();
    let waiter = std::thread::spawn(move || {
        let timeout = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        let result = unsafe { libc::kevent(kq, std::ptr::null(), 0, &mut event, 1, &timeout) };
        completion.store(true, Ordering::Release);
        result == 1 && event.ident == fd as usize && event.filter == libc::EVFILT_READ
    });
    if let Some(exec) = &exec {
        settle(exec);
    }
    assert_eq!(
        unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) },
        0
    );
    let observed = exec
        .as_ref()
        .is_none_or(|exec| !exec.quiescence().quiescent || finished.load(Ordering::Acquire));
    if let Some(exec) = &exec {
        exec.enter_timestamp(Duration::from_secs(1));
        exec.leave_timestamp(Duration::from_secs(1));
    }
    let reported = waiter.join().unwrap();
    assert_eq!(unsafe { libc::close(kq) }, 0);
    (observed, reported)
}

#[cfg(target_os = "macos")]
#[test]
fn kqueue_registration_changes_release_a_waiter_for_an_already_readable_socket() {
    for enable in [false, true] {
        assert_eq!(kqueue_registration_change(enable, false), (true, true));
        let sim = snare::Sim::new();
        sim.pause_time();
        assert_eq!(
            sim.run(|| kqueue_registration_change(enable, true)),
            (true, true)
        );
    }
}
