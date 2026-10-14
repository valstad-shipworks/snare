#![cfg(any(target_os = "linux", target_os = "macos"))]

//! `fcntl` commands on a sim's sockets beyond duplication and the descriptor flags, compared with
//! the host: signal-driven I/O ownership (`F_GETOWN`/`F_SETOWN`, Linux `F_GETOWN_EX`/
//! `F_SETOWN_EX` and `F_GETSIG`/`F_SETSIG`), the status flags `F_SETFL` keeps, macOS
//! `F_GETNOSIGPIPE`/`F_SETNOSIGPIPE`, and the file-only commands a socket refuses.

use std::net::{TcpListener, TcpStream, UdpSocket};
use std::os::fd::AsRawFd;

use snare::Sim;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

/// `fcntl`, its value or `errno`. `F_GETOWN` reports a process group as a negative value, -1
/// included, so a -1 is a failure only when it set `errno`.
fn fcntl(fd: i32, cmd: i32, arg: libc::c_long) -> Result<i32, i32> {
    #[cfg(target_os = "linux")]
    unsafe {
        *libc::__errno_location() = 0
    };
    #[cfg(target_os = "macos")]
    unsafe {
        *libc::__error() = 0
    };
    let rc = unsafe { libc::fcntl(fd, cmd, arg) };
    match errno() {
        e if rc == -1 && e != 0 => Err(e),
        _ => Ok(rc),
    }
}

#[cfg(target_os = "linux")]
const F_SETOWN_EX: i32 = 15;
#[cfg(target_os = "linux")]
const F_GETOWN_EX: i32 = 16;
#[cfg(target_os = "linux")]
const F_SETSIG: i32 = 10;
#[cfg(target_os = "linux")]
const F_GETSIG: i32 = 11;
#[cfg(target_os = "linux")]
const DN_ACCESS: i32 = 1;

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Default, Debug)]
struct FOwnerEx {
    ty: i32,
    pid: i32,
}

#[cfg(target_os = "linux")]
fn owner_ex(fd: i32) -> Result<(i32, i32), i32> {
    let mut owner = FOwnerEx::default();
    fcntl(fd, F_GETOWN_EX, (&raw mut owner) as libc::c_long).map(|_| (owner.ty, owner.pid))
}

#[cfg(target_os = "linux")]
fn set_owner_ex(fd: i32, ty: i32, pid: i32) -> Result<i32, i32> {
    let owner = FOwnerEx { ty, pid };
    fcntl(fd, F_SETOWN_EX, (&raw const owner) as libc::c_long)
}

/// What each command answers on the socket `fd`; process and thread ids are reported relative
/// to the caller's, which differ between runs.
fn commands(label: &str, fd: i32) -> Vec<String> {
    let pid = unsafe { libc::getpid() };
    let pgrp = unsafe { libc::getpgrp() };
    #[cfg(target_os = "linux")]
    let tid = unsafe { libc::gettid() };
    #[cfg(target_os = "macos")]
    let tid = pid;
    let rel = |r: Result<i32, i32>| {
        r.map(|v| match v {
            v if v == pid => "pid".to_string(),
            v if v == tid => "tid".to_string(),
            v if v == -pgrp => "-pgrp".to_string(),
            v => v.to_string(),
        })
    };
    let mut out = Vec::new();
    let mut push = |what: &str, r: String| out.push(format!("{label} {what}: {r}"));
    push("getown", format!("{:?}", rel(fcntl(fd, libc::F_GETOWN, 0))));
    push(
        "setown pid",
        format!("{:?}", fcntl(fd, libc::F_SETOWN, pid as _)),
    );
    push("getown", format!("{:?}", rel(fcntl(fd, libc::F_GETOWN, 0))));
    push(
        "setown -pgrp",
        format!("{:?}", fcntl(fd, libc::F_SETOWN, -pgrp as libc::c_long)),
    );
    push("getown", format!("{:?}", rel(fcntl(fd, libc::F_GETOWN, 0))));
    push("setown 0", format!("{:?}", fcntl(fd, libc::F_SETOWN, 0)));
    push("getown", format!("{:?}", rel(fcntl(fd, libc::F_GETOWN, 0))));
    let flags = fcntl(fd, libc::F_GETFL, 0).unwrap();
    for (what, add) in [
        ("append", libc::O_APPEND),
        ("async", libc::O_ASYNC),
        ("nonblock", libc::O_NONBLOCK),
        ("sync", libc::O_SYNC),
    ] {
        push(
            &format!("setfl {what}"),
            format!(
                "{:?} getfl {:#x}",
                fcntl(fd, libc::F_SETFL, (flags | add) as _),
                fcntl(fd, libc::F_GETFL, 0).unwrap()
            ),
        );
    }
    push(
        "setfl back",
        format!(
            "{:?} getfl {:#x}",
            fcntl(fd, libc::F_SETFL, flags as _),
            fcntl(fd, libc::F_GETFL, 0).unwrap()
        ),
    );
    let mut lock: libc::flock = unsafe { std::mem::zeroed() };
    lock.l_type = libc::F_WRLCK as _;
    lock.l_whence = libc::SEEK_SET as _;
    push(
        "setlk",
        format!(
            "{:?}",
            fcntl(fd, libc::F_SETLK, (&raw mut lock) as libc::c_long)
        ),
    );
    push(
        "getlk",
        format!(
            "{:?}",
            fcntl(fd, libc::F_GETLK, (&raw mut lock) as libc::c_long)
        ),
    );
    #[cfg(target_os = "linux")]
    {
        let rel_ex = |r: Result<(i32, i32), i32>| {
            r.map(|(ty, v)| {
                let v = match v {
                    v if v == tid && v != pid => "tid".to_string(),
                    v if v == pid => "pid".to_string(),
                    v if v == pgrp => "pgrp".to_string(),
                    v => v.to_string(),
                };
                (ty, v)
            })
        };
        push("getown_ex", format!("{:?}", rel_ex(owner_ex(fd))));
        for (ty, who) in [(0, tid), (1, pid), (2, pgrp), (7, pid), (1, 0)] {
            push(
                &format!("setown_ex {ty}"),
                format!(
                    "{:?} getown_ex {:?} getown {:?}",
                    set_owner_ex(fd, ty, who),
                    rel_ex(owner_ex(fd)),
                    rel(fcntl(fd, libc::F_GETOWN, 0))
                ),
            );
        }
        push("getsig", format!("{:?}", fcntl(fd, F_GETSIG, 0)));
        for sig in [libc::SIGIO, 34, 64, 65, -1, 0] {
            push(
                &format!("setsig {sig}"),
                format!(
                    "{:?} getsig {:?}",
                    fcntl(fd, F_SETSIG, sig as _),
                    fcntl(fd, F_GETSIG, 0)
                ),
            );
        }
        push("getlease", format!("{:?}", fcntl(fd, libc::F_GETLEASE, 0)));
        push(
            "setlease",
            format!("{:?}", fcntl(fd, libc::F_SETLEASE, libc::F_RDLCK as _)),
        );
        push(
            "notify",
            format!("{:?}", fcntl(fd, libc::F_NOTIFY, DN_ACCESS as _)),
        );
        push(
            "getpipe_sz",
            format!("{:?}", fcntl(fd, libc::F_GETPIPE_SZ, 0)),
        );
        push(
            "setpipe_sz",
            format!("{:?}", fcntl(fd, libc::F_SETPIPE_SZ, 4096)),
        );
        push(
            "get_seals",
            format!("{:?}", fcntl(fd, libc::F_GET_SEALS, 0)),
        );
        push(
            "add_seals",
            format!("{:?}", fcntl(fd, libc::F_ADD_SEALS, libc::F_SEAL_SEAL as _)),
        );
        push(
            "setfl direct",
            format!(
                "{:?}",
                fcntl(fd, libc::F_SETFL, (flags | libc::O_DIRECT) as _)
            ),
        );
    }
    #[cfg(target_os = "macos")]
    {
        const F_SETNOSIGPIPE: i32 = 73;
        const F_GETNOSIGPIPE: i32 = 74;
        const SO_NOSIGPIPE: i32 = 0x1022;
        let so = |fd: i32| {
            let mut v = 0i32;
            let mut len = 4;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_NOSIGPIPE,
                    (&raw mut v).cast(),
                    &mut len,
                )
            };
            if rc < 0 { Err(errno()) } else { Ok(v) }
        };
        push(
            "getnosigpipe",
            format!("{:?} so {:?}", fcntl(fd, F_GETNOSIGPIPE, 0), so(fd)),
        );
        for v in [0, 1, 2, 0] {
            push(
                &format!("setnosigpipe {v}"),
                format!(
                    "{:?} get {:?} so {:?}",
                    fcntl(fd, F_SETNOSIGPIPE, v),
                    fcntl(fd, F_GETNOSIGPIPE, 0),
                    so(fd)
                ),
            );
        }
        let on = 1i32;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                SO_NOSIGPIPE,
                (&raw const on).cast(),
                4,
            )
        };
        push(
            "so_nosigpipe 1",
            format!("get {:?}", fcntl(fd, F_GETNOSIGPIPE, 0)),
        );
        let mut path = [0u8; libc::PATH_MAX as usize];
        push(
            "getpath",
            format!(
                "{:?}",
                fcntl(fd, libc::F_GETPATH, path.as_mut_ptr() as libc::c_long)
            ),
        );
        push(
            "fullfsync",
            format!("{:?}", fcntl(fd, libc::F_FULLFSYNC, 0)),
        );
        push("nocache", format!("{:?}", fcntl(fd, libc::F_NOCACHE, 1)));
        push("rdahead", format!("{:?}", fcntl(fd, libc::F_RDAHEAD, 1)));
    }
    push("unknown", format!("{:?}", fcntl(fd, 0x7777, 0)));
    out
}

fn scenario() -> Vec<String> {
    let udp = UdpSocket::bind("127.0.0.1:0").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let mut out = commands("udp", udp.as_raw_fd());
    out.extend(commands("listener", listener.as_raw_fd()));
    out.extend(commands("stream", client.as_raw_fd()));
    out
}

#[test]
fn fcntl_os_truth() {
    let real = scenario();
    let sim = Sim::builder().strict_sockopts().build().run(scenario);
    let diff: Vec<String> = real
        .iter()
        .zip(&sim)
        .filter(|(r, s)| r != s)
        .map(|(r, s)| format!("real {r}\n sim {s}"))
        .collect();
    assert!(diff.is_empty(), "{}", diff.join("\n"));
    assert_eq!(real.len(), sim.len());
}
