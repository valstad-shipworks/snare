//! Behaviour pins for large topologies, ahead of performance work on interface and route lookup:
//! 250 interfaces take indexes 2, 3, 4, … after `lo` and list in that order, with `sim0` last;
//! with ten thousand overlapping routes on top, a thousand lookups each pick the longest prefix,
//! then the lowest metric, then the route added first, with the egress interface's own address as
//! the
//! source — checked against a model of that rule and pinned to a golden; removing half the routes
//! moves exactly the lookups they carried; and a datagram sent through the table leaves by the
//! interface the lookup named.

#![cfg(unix)]

#[path = "support/golden.rs"]
mod golden;

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

use snare::{IpNet, NicSpec, Route, Sim};

const NICS: usize = 250;
const ROUTES: usize = 10_000;

fn nic_name(i: usize) -> String {
    format!("eth{i}")
}

fn nic_addr(i: usize) -> Ipv4Addr {
    Ipv4Addr::new(10, (i / 250) as u8 + 1, (i % 250) as u8, 1)
}

/// Route `j`: a /24, /20 or /16 inside 172.16.0.0/12, on interface `j % NICS`, metric `j % 7`.
fn route(j: usize) -> (IpNet, usize, u32) {
    let prefix = [24u8, 20, 16][j % 3];
    let b = 16 + (j / 256 % 16) as u8;
    let c = (j % 256) as u8;
    let net = IpNet::new(IpAddr::V4(Ipv4Addr::new(172, b, c, 0)), prefix);
    let net = IpNet::new(net.network(), prefix);
    (net, j % NICS, (j % 7) as u32)
}

/// The destinations looked up: spread over 172.16.0.0/12 and a few outside it.
fn destination(k: usize) -> IpAddr {
    let k = k as u32;
    if k % 50 == 49 {
        return IpAddr::V4(Ipv4Addr::new(8, 8, (k / 50) as u8, 8));
    }
    IpAddr::V4(Ipv4Addr::new(
        172,
        16 + (k * 7 % 16) as u8,
        (k * 37 % 256) as u8,
        (k % 254 + 1) as u8,
    ))
}

fn build() -> Sim {
    let mut builder = Sim::builder();
    for i in 0..NICS {
        builder =
            builder.nic(NicSpec::new(nic_name(i)).address(IpNet::new(IpAddr::V4(nic_addr(i)), 24)));
    }
    let sim = builder.build();
    for j in 0..ROUTES {
        let (dest, nic, metric) = route(j);
        sim.add_route(Route::new(dest, nic_name(nic)).metric(metric))
            .unwrap();
    }
    sim
}

/// The model's choice for `dst` among routes `live`: longest prefix, then lowest metric, then
/// added first; `None` when only the default route matches.
fn model(dst: IpAddr, live: impl Iterator<Item = usize>) -> Option<usize> {
    live.filter(|&j| route(j).0.contains(dst))
        .min_by_key(|&j| (std::cmp::Reverse(route(j).0.prefix), route(j).2, j))
        .map(|j| route(j).1)
}

#[test]
fn two_hundred_fifty_interfaces_take_indexes_in_order() {
    let sim = build();
    let nics = sim.nics();
    assert_eq!(nics.len(), NICS + 2);
    assert!(nics[0].loopback);
    let last = &nics[NICS + 1];
    assert_eq!(
        (last.index, last.spec.name.as_str()),
        (NICS as u32 + 2, "sim0")
    );
    for (i, nic) in nics[1..=NICS].iter().enumerate() {
        assert_eq!(
            (nic.index, nic.spec.name.as_str()),
            (i as u32 + 2, nic_name(i).as_str())
        );
    }
}

#[test]
fn ten_thousand_routes_resolve_by_prefix_metric_then_age() {
    let sim = build();
    let mut out = String::new();
    for k in 0..1_000 {
        let dst = destination(k);
        let choice = sim.route_lookup(None, dst).unwrap();
        let want = model(dst, 0..ROUTES).map_or("sim0".to_string(), nic_name);
        assert_eq!(choice.nic, want, "lookup of {dst}");
        if let Some(i) = model(dst, 0..ROUTES) {
            assert_eq!(
                choice.src,
                Some(IpAddr::V4(nic_addr(i))),
                "source for {dst}"
            );
            assert_eq!(choice.index, i as u32 + 2);
        }
        out.push_str(&format!(
            "{dst} {} {} {:?} {:?}\n",
            choice.nic, choice.index, choice.src, choice.gateway
        ));
    }
    golden::check_text("edge_scale_routes.txt", &out);
}

#[test]
fn removing_half_the_routes_moves_exactly_their_lookups() {
    let sim = build();
    let before: Vec<String> = (0..1_000)
        .map(|k| sim.route_lookup(None, destination(k)).unwrap().nic)
        .collect();
    let mut removed = 0;
    for j in (0..ROUTES).filter(|j| j % 2 == 0) {
        if sim.remove_route(route(j).0) {
            removed += 1;
        }
    }
    let gone: std::collections::HashSet<IpNet> = (0..ROUTES)
        .filter(|j| j % 2 == 0)
        .map(|j| route(j).0)
        .collect();
    let live: Vec<usize> = (0..ROUTES)
        .filter(|&j| !gone.contains(&route(j).0))
        .collect();
    let mut moved = 0;
    for (k, was) in before.iter().enumerate() {
        let dst = destination(k);
        let now = sim.route_lookup(None, dst).unwrap().nic;
        let want = model(dst, live.iter().copied()).map_or("sim0".to_string(), nic_name);
        assert_eq!(now, want, "lookup of {dst} after removal");
        moved += usize::from(&now != was);
    }
    assert_eq!(
        (removed, moved),
        (1_939, 595),
        "(destinations removed, lookups moved)"
    );
}

#[test]
fn a_datagram_leaves_by_the_interface_the_lookup_names() {
    let sim = build();
    let dst = destination(3);
    let want = sim.route_lookup(None, dst).unwrap();
    sim.run(|| {
        let sock = UdpSocket::bind("0.0.0.0:0").unwrap();
        sock.send_to(b"x", (dst, 9)).unwrap();
        let e = snare::socket_entry(snare::socket_id(&sock).unwrap()).unwrap();
        assert_eq!(e.last_tx_nic.as_deref(), Some(want.nic.as_str()));
    });
}
