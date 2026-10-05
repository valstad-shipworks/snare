//! Name resolution for a domain. With a [`Resolver`], a managed thread's `getaddrinfo`,
//! `getnameinfo` and `gethostbyname` (and their Winsock wide forms) answer names from it instead
//! of the system resolver. Numeric hosts, a missing node and service names never reach it: they go
//! to the OS's own code, so hints and error precedence stay the host's.

use std::net::IpAddr;

/// What a forward lookup of one name found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    /// The name's addresses, in the order they are returned, and its canonical name.
    Addrs {
        /// Reported as `ai_canonname` when the caller asks for it, and as `h_name`.
        canonical: String,
        /// May be empty: a known name with no address fails as the OS fails a name with no
        /// address of the asked family.
        addrs: Vec<IpAddr>,
    },
    /// No such name: `EAI_NONAME` / `WSAHOST_NOT_FOUND` (`HOST_NOT_FOUND` from `gethostbyname`).
    NotFound,
    /// A temporary failure: `EAI_AGAIN` / `WSATRY_AGAIN` (`TRY_AGAIN`).
    TryAgain,
    /// A permanent failure: `EAI_FAIL` / `WSANO_RECOVERY` (`NO_RECOVERY`).
    Fail,
    /// Ask the system resolver, with the thread in passthrough.
    Real,
}

/// What a reverse lookup of one address found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reverse {
    /// The address's host name, written to the caller's host buffer.
    Name(String),
    /// No name: `getnameinfo` returns the numeric form, or fails under `NI_NAMEREQD`.
    NotFound,
    /// Ask the system resolver.
    Real,
}

/// Answers a domain's name lookups. Called from the resolver hooks with the calling thread in
/// passthrough, so it may block in the sim's own waits.
pub trait Resolver: Send + Sync + 'static {
    /// Forward lookup of `name` exactly as the caller spelled it; matching case-insensitively, as
    /// DNS does (RFC 4343), is the resolver's business.
    fn lookup(&self, name: &str) -> Lookup;

    /// Reverse lookup of `ip`, a v4-mapped IPv6 address already unwrapped to IPv4. Defaults to
    /// [`Reverse::NotFound`].
    fn reverse(&self, _ip: IpAddr) -> Reverse {
        Reverse::NotFound
    }
}
