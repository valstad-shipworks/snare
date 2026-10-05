//! Behaviour pin for running out of descriptors at scale: a sim socket is a real descriptor
//! `dup`ed from `/dev/null`, so the process's own `RLIMIT_NOFILE` bounds how many the code under
//! test can open. With the soft limit lowered to a few hundred past what the process holds, UDP
//! and TCP sockets open until exactly that limit, the next `socket` fails with `EMFILE`, a failed
//! socket leaves no record in the socket table and takes no socket id, and closing one lets the
//! next open succeed.
//!
//! A test binary of its own: the limit is process-wide, and lowering it would fail any test
//! running beside it.

#![cfg(unix)]

use std::net::{SocketAddr, TcpListener, UdpSocket};

use snare::Sim;

/// How many descriptors past those already open the limit allows.
const HEADROOM: usize = 300;

/// Descriptors open in the process, not counting the one listing them.
fn open_fds() -> usize {
    let dir = if cfg!(target_os = "linux") {
        "/proc/self/fd"
    } else {
        "/dev/fd"
    };
    std::fs::read_dir(dir).unwrap().count() - 1
}

/// Sets the soft descriptor limit, returning the old limits.
fn set_soft_nofile(soft: usize) -> libc::rlimit {
    let mut old = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `old` is a live rlimit.
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut old) }, 0);
    let new = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: old.rlim_max,
    };
    // SAFETY: `new` is a live rlimit.
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &new) }, 0);
    old
}

#[test]
fn sockets_open_up_to_the_descriptor_limit_then_fail_with_emfile() {
    let sim = Sim::new();
    sim.run(|| drop(UdpSocket::bind("127.0.0.1:1").unwrap()));
    let held = open_fds();
    let old = set_soft_nofile(held + HEADROOM);

    let outcome = sim.run(|| {
        let mut socks = Vec::new();
        let err = loop {
            let port = 20_000 + socks.len() as u16;
            match UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], port))) {
                Ok(s) => socks.push(s),
                Err(e) => break e,
            }
        };
        let opened = socks.len();
        let table = snare::socket_table().len();
        let listener = TcpListener::bind("127.0.0.1:7000")
            .map(|_| ())
            .map_err(|e| e.raw_os_error());
        let ids_before = snare::socket_table().last().map(|e| e.id.get());
        socks.pop();
        let after = UdpSocket::bind("127.0.0.1:30000").unwrap();
        let next_id = snare::socket_id(&after).unwrap().get();
        (
            opened,
            err.raw_os_error(),
            table,
            listener,
            ids_before,
            next_id,
        )
    });
    set_soft_nofile(old.rlim_cur as usize);

    assert_eq!(
        outcome,
        (
            HEADROOM,
            Some(libc::EMFILE),
            HEADROOM,
            Err(Some(libc::EMFILE)),
            Some(HEADROOM as u64 + 1),
            HEADROOM as u64 + 2,
        ),
        "(opened, errno, table rows, listener, last id, id after a close)"
    );
    assert_eq!(sim.closed_sockets().len(), HEADROOM + 2);
}
