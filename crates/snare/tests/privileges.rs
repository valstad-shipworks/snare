#![cfg(unix)]

//! One privileges model per sim: what the code under test may do, gating reserved-port binds,
//! interface rebinds, packet priorities, raw sockets and BPF devices as the host OS does, and
//! agreeing with a `SimHost`'s capabilities.

use std::net::{TcpListener, UdpSocket};

use snare::{HostProfile, Privileges, Sim};

fn denied(r: std::io::Result<impl Sized>) -> Option<i32> {
    r.err().and_then(|e| e.raw_os_error())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn plain_sim_defaults_to_all_privileges() {
    let sim = Sim::new();
    assert_eq!(sim.privileges(), Privileges::all());
    sim.run(|| {
        assert_eq!(snare::privileges(), Privileges::all());
        UdpSocket::bind("127.0.0.1:999").unwrap();
        TcpListener::bind("127.0.0.1:998").unwrap();
    });
}

#[cfg(target_os = "linux")]
mod linux {
    use std::net::{TcpListener, UdpSocket};
    use std::os::fd::AsRawFd;

    use snare::{CAP_NET_ADMIN, CAP_NET_BIND_SERVICE, CAP_NET_RAW, CAP_SYS_NICE, HostProfile};
    use snare::{Privileges, Sim};

    use super::denied;

    fn errno() -> i32 {
        std::io::Error::last_os_error().raw_os_error().unwrap()
    }

    fn set_opt(fd: i32, name: i32, val: &[u8]) -> Result<(), i32> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                name,
                val.as_ptr().cast(),
                val.len() as u32,
            )
        };
        if rc == 0 { Ok(()) } else { Err(errno()) }
    }

    #[test]
    fn linux_low_port_bind_needs_net_bind_service() {
        let sim = Sim::builder().privileges(Privileges::none()).build();
        sim.run(|| {
            assert_eq!(denied(UdpSocket::bind("127.0.0.1:999")), Some(libc::EACCES));
            assert_eq!(denied(UdpSocket::bind("0.0.0.0:999")), Some(libc::EACCES));
            assert_eq!(
                denied(TcpListener::bind("127.0.0.1:999")),
                Some(libc::EACCES)
            );
            UdpSocket::bind("127.0.0.1:1024").unwrap();
            UdpSocket::bind("127.0.0.1:0").unwrap();
            snare::set_privileges(|p| p.net_bind_service = true);
            UdpSocket::bind("127.0.0.1:999").unwrap();
            TcpListener::bind("127.0.0.1:999").unwrap();
        });

        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(|| {
                assert_eq!(denied(UdpSocket::bind("127.0.0.1:999")), Some(libc::EACCES));
            });
        let host = HostProfile::new().cap(CAP_NET_BIND_SERVICE).build();
        Sim::builder().host(host).build().run(|| {
            UdpSocket::bind("127.0.0.1:999").unwrap();
        });
    }

    #[test]
    fn linux_bindtodevice_rebind_needs_net_raw() {
        let sim = Sim::builder().privileges(Privileges::none()).build();
        sim.run(|| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = s.as_raw_fd();
            set_opt(fd, libc::SO_BINDTODEVICE, b"lo\0").unwrap();
            assert_eq!(
                set_opt(fd, libc::SO_BINDTODEVICE, b"lo\0"),
                Err(libc::EPERM)
            );
            assert_eq!(set_opt(fd, libc::SO_BINDTODEVICE, b""), Err(libc::EPERM));
            snare::set_privileges(|p| p.net_raw = true);
            set_opt(fd, libc::SO_BINDTODEVICE, b"").unwrap();
        });
    }

    #[test]
    fn linux_priority_above_6_needs_net_admin_or_raw() {
        let check = |granted: bool| {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            let fd = s.as_raw_fd();
            set_opt(fd, libc::SO_PRIORITY, &6i32.to_ne_bytes()).unwrap();
            for v in [7i32, -1] {
                let want = if granted { Ok(()) } else { Err(libc::EPERM) };
                assert_eq!(set_opt(fd, libc::SO_PRIORITY, &v.to_ne_bytes()), want);
            }
            let want = if granted { Ok(()) } else { Err(libc::EPERM) };
            assert_eq!(set_opt(fd, libc::SO_MARK, &1u32.to_ne_bytes()), want);
        };
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(|| check(false));
        for cap in [CAP_NET_ADMIN, CAP_NET_RAW] {
            Sim::builder()
                .host(HostProfile::new().cap(cap).build())
                .build()
                .run(|| check(true));
        }
    }

    #[test]
    fn linux_af_packet_needs_net_raw() {
        let sim = Sim::builder().privileges(Privileges::none()).build();
        sim.run(|| {
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
            assert_eq!((fd, errno()), (-1, libc::EPERM));
            snare::set_privileges(|p| p.net_raw = true);
            let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
            assert!(fd >= 0);
            unsafe { libc::close(fd) };
        });
    }

    fn set_fifo() -> i32 {
        let param = libc::sched_param { sched_priority: 10 };
        let rc = unsafe { libc::sched_setscheduler(0, libc::SCHED_FIFO, &param) };
        if rc == 0 { 0 } else { errno() }
    }

    fn cap_eff() -> u64 {
        let status = std::fs::read_to_string("/proc/self/status").unwrap();
        let line = status.lines().find(|l| l.starts_with("CapEff:")).unwrap();
        u64::from_str_radix(line.split_whitespace().nth(1).unwrap(), 16).unwrap()
    }

    #[test]
    fn simhost_caps_and_set_privileges_agree() {
        let host = HostProfile::new().cap(CAP_SYS_NICE).build();
        let sim = Sim::builder().host(host).build();
        assert!(sim.privileges().sys_nice);
        assert!(!sim.privileges().net_admin);
        sim.run(|| {
            assert_eq!(set_fifo(), 0);
            assert_eq!(unsafe { libc::geteuid() }, 1000);
            assert_eq!(unsafe { libc::getuid() }, 1000);
            assert_eq!(cap_eff(), 1 << CAP_SYS_NICE);
            snare::set_privileges(|p| p.sys_nice = false);
            assert_eq!(
                set_fifo(),
                0,
                "keeping the same real-time priority needs no privilege"
            );
            let other = libc::sched_param { sched_priority: 0 };
            assert_eq!(
                unsafe { libc::sched_setscheduler(0, libc::SCHED_OTHER, &other) },
                0
            );
            assert_eq!(
                set_fifo(),
                libc::EPERM,
                "entering it again with RLIMIT_RTPRIO 0"
            );
            assert_eq!(cap_eff(), 0);
            snare::set_privileges(|p| {
                p.root = true;
                p.net_admin = true;
            });
            assert_eq!(unsafe { libc::geteuid() }, 0);
            assert_eq!(cap_eff(), 1 << CAP_NET_ADMIN);
        });

        let host = HostProfile::new().root(true).build();
        Sim::builder()
            .host(host)
            .privileges(Privileges::all())
            .build()
            .run(|| {
                assert_eq!(unsafe { libc::geteuid() }, 0);
                assert_eq!(set_fifo(), 0);
            });
    }
}

#[cfg(target_os = "macos")]
mod macos {
    use std::net::{TcpListener, UdpSocket};

    use snare::{HostProfile, Privileges, Sim};

    use super::denied;

    #[test]
    fn macos_low_port_specific_address_needs_root() {
        let sim = Sim::builder().privileges(Privileges::none()).build();
        sim.run(|| {
            assert_eq!(denied(UdpSocket::bind("127.0.0.1:999")), Some(libc::EACCES));
            assert_eq!(
                denied(TcpListener::bind("127.0.0.1:999")),
                Some(libc::EACCES)
            );
            UdpSocket::bind("0.0.0.0:999").unwrap();
            UdpSocket::bind("127.0.0.1:1024").unwrap();
            snare::set_privileges(|p| p.root = true);
            UdpSocket::bind("127.0.0.1:997").unwrap();
        });
    }

    #[test]
    fn macos_bpf_open_needs_root() {
        let sim = Sim::builder().privileges(Privileges::none()).build();
        sim.run(|| {
            let err = std::fs::File::open("/dev/bpf0").unwrap_err();
            assert_eq!(err.raw_os_error(), Some(libc::EACCES));
            snare::set_privileges(|p| p.root = true);
            std::fs::File::open("/dev/bpf0").unwrap();
        });
    }

    #[test]
    fn simhost_geteuid_follows_root() {
        Sim::builder()
            .host(HostProfile::new().build())
            .build()
            .run(|| {
                assert_eq!(unsafe { libc::geteuid() }, 501);
                snare::set_privileges(|p| p.root = true);
                assert_eq!(unsafe { libc::geteuid() }, 0);
            });
        Sim::builder()
            .host(HostProfile::new().root(true).build())
            .build()
            .run(|| assert_eq!(unsafe { libc::getuid() }, 0));
    }
}

#[test]
fn sim_handle_sets_privileges_from_outside() {
    let sim = Sim::builder().host(HostProfile::new().build()).build();
    assert_eq!(sim.privileges(), Privileges::none());
    sim.set_privileges(|p| {
        p.net_bind_service = true;
        p.root = true;
    });
    sim.run(|| {
        assert!(snare::privileges().net_bind_service);
        UdpSocket::bind("127.0.0.1:996").unwrap();
    });
}
