//! Binding a TCP address that overlaps one already held — a wildcard and a specific address on one
//! port, or the same address twice — succeeds or fails in the sim exactly as on the host OS, for
//! every combination of SO_REUSEADDR on either socket and the held one listening or not.

#[path = "support/rawsock.rs"]
mod rawsock;

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use snare::Sim;

const WILDCARD: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

#[derive(Clone, Copy, Debug)]
struct Case {
    held: IpAddr,
    want: IpAddr,
    held_reuse: bool,
    want_reuse: bool,
    listening: bool,
}

fn cases() -> Vec<Case> {
    let mut out = Vec::new();
    for (held, want) in [
        (WILDCARD, LOOPBACK),
        (LOOPBACK, WILDCARD),
        (LOOPBACK, LOOPBACK),
        (WILDCARD, WILDCARD),
    ] {
        for bits in 0..8 {
            out.push(Case {
                held,
                want,
                held_reuse: bits & 1 != 0,
                want_reuse: bits & 2 != 0,
                listening: bits & 4 != 0,
            });
        }
    }
    out
}

/// Whether the second bind of `case` succeeds, or the error it fails with.
fn second_bind(case: Case) -> Result<(), i32> {
    let held = rawsock::tcp_socket(false);
    rawsock::set_reuseaddr(held, case.held_reuse);
    rawsock::bind(held, SocketAddr::new(case.held, 0)).unwrap();
    if case.listening {
        rawsock::listen(held);
    }
    let port = rawsock::local_port(held);
    let want = rawsock::tcp_socket(false);
    rawsock::set_reuseaddr(want, case.want_reuse);
    let result = rawsock::bind(want, SocketAddr::new(case.want, port));
    rawsock::close(want);
    rawsock::close(held);
    result
}

#[test]
fn overlapping_binds_match_the_host() {
    let real: Vec<_> = cases().into_iter().map(|c| (c, second_bind(c))).collect();
    let simulated: Vec<_> =
        Sim::new().run(|| cases().into_iter().map(|c| (c, second_bind(c))).collect());
    let differ: Vec<String> = real
        .iter()
        .zip(&simulated)
        .filter(|((_, real), (_, sim))| real != sim)
        .map(|((case, real), (_, sim))| format!("{case:?}: host {real:?}, sim {sim:?}"))
        .collect();
    assert!(differ.is_empty(), "{}", differ.join("\n"));
}
