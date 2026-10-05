#![cfg(target_os = "linux")]
//! Linux busy polling options are kept and read back with the kernel's checks (net/core/sock.c
//! `sk_setsockopt`, measured on Linux 7.0): `SO_BUSY_POLL` takes any non-negative value
//! unprivileged; turning `SO_PREFER_BUSY_POLL` on needs `CAP_NET_ADMIN`; raising
//! `SO_BUSY_POLL_BUDGET` above its current value needs `CAP_NET_ADMIN` and it must fit a `u16`,
//! and it cannot be read back (`ENOPROTOOPT`). An accepted socket takes its listener's. They
//! change nothing about delivery in the sim.
//! `busy_poll_os_truth` compares with the real kernel under the process's own capabilities.

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

use snare::{Privileges, Sim};

const SO_BUSY_POLL: i32 = 46;
const SO_PREFER_BUSY_POLL: i32 = 69;
const SO_BUSY_POLL_BUDGET: i32 = 70;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn set(fd: i32, name: i32, value: i32) -> Result<(), i32> {
    let rc = unsafe { libc::setsockopt(fd, libc::SOL_SOCKET, name, (&raw const value).cast(), 4) };
    if rc == 0 { Ok(()) } else { Err(errno()) }
}

fn get(fd: i32, name: i32) -> Result<i32, i32> {
    let mut v = 0i32;
    let mut len = 4u32;
    let rc = unsafe { libc::getsockopt(fd, libc::SOL_SOCKET, name, (&raw mut v).cast(), &mut len) };
    if rc == 0 { Ok(v) } else { Err(errno()) }
}

fn probe_fd(fd: i32) -> Vec<String> {
    let mut out = Vec::new();
    let mut step = |what: &str, r: Result<i32, i32>| out.push(format!("{what} {r:?}"));
    step("get busy_poll", get(fd, SO_BUSY_POLL));
    step("get prefer", get(fd, SO_PREFER_BUSY_POLL));
    step("get budget", get(fd, SO_BUSY_POLL_BUDGET));
    for v in [50, 10, -1, i32::MAX] {
        step(
            &format!("set busy_poll {v}"),
            set(fd, SO_BUSY_POLL, v).map(|()| 0),
        );
        step("get busy_poll", get(fd, SO_BUSY_POLL));
    }
    for v in [1, 5, -3, 0] {
        step(
            &format!("set prefer {v}"),
            set(fd, SO_PREFER_BUSY_POLL, v).map(|()| 0),
        );
        step("get prefer", get(fd, SO_PREFER_BUSY_POLL));
    }
    for v in [8, 0, -1, 65535, 65536, 3, 2, 3] {
        step(
            &format!("set budget {v}"),
            set(fd, SO_BUSY_POLL_BUDGET, v).map(|()| 0),
        );
    }
    let byte = 1u8;
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            SO_BUSY_POLL,
            (&raw const byte).cast(),
            1,
        )
    };
    step("short set", if rc == 0 { Ok(0) } else { Err(errno()) });
    out
}

fn probe() -> Vec<String> {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut out = probe_fd(udp.as_raw_fd());
    out.extend(probe_fd(tcp.as_raw_fd()));
    let _ = set(tcp.as_raw_fd(), SO_BUSY_POLL, 33);
    let _ = set(tcp.as_raw_fd(), SO_PREFER_BUSY_POLL, 1);
    let _client = TcpStream::connect(tcp.local_addr().unwrap()).unwrap();
    let (accepted, _) = tcp.accept().unwrap();
    for name in [SO_BUSY_POLL, SO_PREFER_BUSY_POLL] {
        out.push(format!(
            "accepted {name} {:?}",
            get(accepted.as_raw_fd(), name)
        ));
    }
    out
}

#[test]
fn busy_poll_os_truth() {
    let real = snare::real(probe);
    let privileges = Privileges::from_real_process().unwrap();
    let simulated = Sim::builder()
        .privileges(privileges.clone())
        .build()
        .run(probe);
    assert_eq!(simulated, real, "CAP_NET_ADMIN {}", privileges.net_admin);
}

fn sim(net_admin: bool) -> Sim {
    Sim::builder()
        .privileges(Privileges {
            net_admin,
            ..Privileges::none()
        })
        .strict_sockopts()
        .build()
}

#[test]
fn busy_poll_is_kept_unprivileged() {
    sim(false).run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = s.as_raw_fd();
        assert_eq!(get(fd, SO_BUSY_POLL), Ok(0));
        assert_eq!(set(fd, SO_BUSY_POLL, 50), Ok(()));
        assert_eq!(get(fd, SO_BUSY_POLL), Ok(50));
        assert_eq!(set(fd, SO_BUSY_POLL, -1), Err(libc::EINVAL));
        assert_eq!(set(fd, SO_PREFER_BUSY_POLL, 1), Err(libc::EPERM));
        assert_eq!(set(fd, SO_PREFER_BUSY_POLL, 0), Ok(()));
        assert_eq!(set(fd, SO_BUSY_POLL_BUDGET, 8), Err(libc::EPERM));
        assert_eq!(set(fd, SO_BUSY_POLL_BUDGET, 0), Ok(()));
        assert_eq!(set(fd, SO_BUSY_POLL_BUDGET, -1), Err(libc::EINVAL));
        assert_eq!(get(fd, SO_BUSY_POLL_BUDGET), Err(libc::ENOPROTOOPT));
        let entry = snare::socket_entry(snare::socket_id(&s).unwrap()).unwrap();
        assert!(
            entry.unmodelled_options.is_empty(),
            "modelled under strict mode"
        );
    });
}

#[test]
fn busy_poll_privileged() {
    sim(true).run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let fd = s.as_raw_fd();
        assert_eq!(set(fd, SO_PREFER_BUSY_POLL, 7), Ok(()));
        assert_eq!(get(fd, SO_PREFER_BUSY_POLL), Ok(1));
        assert_eq!(set(fd, SO_BUSY_POLL_BUDGET, 65535), Ok(()));
        assert_eq!(set(fd, SO_BUSY_POLL_BUDGET, 65536), Err(libc::EINVAL));
        snare::set_privileges(|p| *p = Privileges::none());
        assert_eq!(
            set(fd, SO_BUSY_POLL_BUDGET, 64),
            Ok(()),
            "lowering needs nothing"
        );
        assert_eq!(set(fd, SO_BUSY_POLL_BUDGET, 65), Err(libc::EPERM));
        assert_eq!(set(fd, SO_PREFER_BUSY_POLL, 0), Ok(()));
        assert_eq!(get(fd, SO_PREFER_BUSY_POLL), Ok(0));
    });
}

/// A `SimHost`'s datagram and netlink sockets take the same options.
#[test]
fn busy_poll_on_simhost_sockets() {
    let host = snare::HostProfile::new().build();
    Sim::builder()
        .host(host)
        .privileges(Privileges::none())
        .build()
        .run(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let nl = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_ROUTE) };
            assert!(nl >= 0);
            for fd in [s.as_raw_fd(), nl] {
                assert_eq!(set(fd, SO_BUSY_POLL, 25), Ok(()));
                assert_eq!(get(fd, SO_BUSY_POLL), Ok(25));
                assert_eq!(set(fd, SO_PREFER_BUSY_POLL, 1), Err(libc::EPERM));
            }
            unsafe { libc::close(nl) };
        });
}
