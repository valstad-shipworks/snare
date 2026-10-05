//! Address resolution for the shim's sockets. Numeric addresses resolve as
//! std does; names go to [`add_host`](crate::add_host) entries and the
//! emulated OS's `localhost` before they can reach the host's resolver.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::{LazyLock, Mutex};
use std::vec;

use crate::os::OsSemantics;

/// snare's counterpart of [`std::net::ToSocketAddrs`], implemented for the
/// same types. Under the shim every snare socket takes addresses through it,
/// so a hostname resolves inside the sim ([`add_host`](crate::add_host),
/// `localhost`) instead of through the host's `getaddrinfo`, which would
/// block for real time and make the run depend on the host.
///
/// A name the sim cannot resolve is refused with an error, and recorded as
/// a fatal audit violation, in audit mode (`SNARE_SCHED_AUDIT`, or a driver
/// with audit on). Otherwise it goes to the host's resolver after a
/// one-time warning per name. `SNARE_REAL_DNS=1` always uses the host's
/// resolver for such names.
pub trait ToSocketAddrs {
    type Iter: Iterator<Item = SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter>;
}

macro_rules! numeric {
    ($($ty:ty),*) => {$(
        impl ToSocketAddrs for $ty {
            type Iter = std::option::IntoIter<SocketAddr>;

            fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
                std::net::ToSocketAddrs::to_socket_addrs(self)
            }
        }
    )*};
}

numeric!(
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
    (IpAddr, u16),
    (Ipv4Addr, u16),
    (Ipv6Addr, u16)
);

impl ToSocketAddrs for (&str, u16) {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        let (host, port) = *self;
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)].into_iter());
        }
        lookup_host(host, port)
    }
}

impl ToSocketAddrs for (String, u16) {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        (&*self.0, self.1).to_socket_addrs()
    }
}

impl ToSocketAddrs for str {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        if let Ok(addr) = self.parse::<SocketAddr>() {
            return Ok(vec![addr].into_iter());
        }
        let (host, port) = self
            .rsplit_once(':')
            .ok_or_else(|| invalid_input("invalid socket address"))?;
        let port: u16 = port
            .parse()
            .map_err(|_| invalid_input("invalid port value"))?;
        (host, port).to_socket_addrs()
    }
}

impl ToSocketAddrs for String {
    type Iter = vec::IntoIter<SocketAddr>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        (**self).to_socket_addrs()
    }
}

impl<'a> ToSocketAddrs for &'a [SocketAddr] {
    type Iter = std::iter::Cloned<std::slice::Iter<'a, SocketAddr>>;

    fn to_socket_addrs(&self) -> io::Result<Self::Iter> {
        Ok(self.iter().cloned())
    }
}

impl<T: ToSocketAddrs + ?Sized> ToSocketAddrs for &T {
    type Iter = T::Iter;

    fn to_socket_addrs(&self) -> io::Result<T::Iter> {
        (**self).to_socket_addrs()
    }
}

fn invalid_input(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, msg)
}

/// What the emulated OS's resolver answers for `localhost` with no hosts
/// file override: the IPv6 loopback first, as getaddrinfo orders it on
/// Linux, macOS and Windows.
fn localhost(_os: OsSemantics) -> Vec<IpAddr> {
    vec![
        IpAddr::V6(Ipv6Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
    ]
}

fn real_dns() -> bool {
    std::env::var("SNARE_REAL_DNS").is_ok_and(|v| !v.is_empty() && v != "0")
}

fn lookup_host(name: &str, port: u16) -> io::Result<vec::IntoIter<SocketAddr>> {
    let ips = crate::state::host_addrs(name).or_else(|| {
        name.trim_end_matches('.')
            .eq_ignore_ascii_case("localhost")
            .then(|| localhost(crate::state::os_ctx().0))
    });
    if let Some(ips) = ips {
        let addrs: Vec<_> = ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        return Ok(addrs.into_iter());
    }
    if !real_dns() {
        if crate::sched::strict() {
            crate::sched::fatal_violation("host dns lookup");
            return Err(io::Error::other(format!(
                "snare: refusing to resolve {name:?} through the host's resolver in audit mode; \
                 register it with snare::add_host or set SNARE_REAL_DNS=1"
            )));
        }
        warn_once(name);
    }
    let addrs: Vec<_> = std::net::ToSocketAddrs::to_socket_addrs(&(name, port))?.collect();
    Ok(addrs.into_iter())
}

fn warn_once(name: &str) {
    static WARNED: LazyLock<Mutex<HashSet<String>>> = LazyLock::new(Default::default);
    let mut warned = WARNED.lock().unwrap_or_else(|e| e.into_inner());
    if warned.insert(name.to_ascii_lowercase()) {
        eprintln!(
            "snare: WARN resolving {name:?} through the host's resolver: it blocks for real \
             time and its answer depends on the host; register it with snare::add_host"
        );
    }
}
