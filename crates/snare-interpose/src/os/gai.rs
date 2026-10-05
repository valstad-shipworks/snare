//! The `getaddrinfo` algorithm every resolver hook shares, over the list type and character width
//! of one flavour of the call (`addrinfo`, `ADDRINFOA`, `ADDRINFOW`).
//!
//! A name the [`Resolver`] knows is answered by asking the OS for each of its addresses as a
//! numeric host, with the caller's hints, and linking the lists the OS returns. Every node is the
//! OS's own, so socket types, protocols, ports and family handling are exactly the host's; the
//! joined list is remembered so that freeing it hands each piece back to the OS separately.
//!
//! Joined lists live in [`CHAINS`], keyed by head address, process-wide: a list may be freed on
//! any thread, inside or outside the domain that built it. The lock is only taken with the thread
//! in passthrough, so the mutex's own blocking calls go to the OS rather than to a domain.

use std::collections::BTreeMap;
use std::ffi::c_int;
use std::net::IpAddr;
use std::sync::Mutex;
use std::{mem, ptr};

use crate::domain;
use crate::resolve::{Lookup, Resolver};
use crate::state::Passthrough;

/// One flavour of `getaddrinfo`: its list node, its character type, its flags and its codes.
///
/// The constants are the flavour's own values of the POSIX names (IEEE Std 1003.1, `freeaddrinfo`
/// page, which specifies `getaddrinfo`); the error codes are what the call returns for a resolver
/// [`Lookup`].
pub(crate) trait Flavor {
    /// The list node: `addrinfo`, `ADDRINFOA` or `ADDRINFOW`.
    type Node;
    /// The character type of names: `c_char`, `u8` or `u16`.
    type Char: Copy;

    const AF_INET6: c_int;
    const AI_NUMERICHOST: c_int;
    /// The flags that ask for `ai_canonname`.
    const AI_CANONICAL: c_int;
    const AI_ADDRCONFIG: c_int;
    const AI_V4MAPPED: c_int;
    const AI_ALL: c_int;
    /// No such name ([`Lookup::NotFound`]): `EAI_NONAME` / `WSAHOST_NOT_FOUND`.
    const NONAME: c_int;
    /// A temporary failure ([`Lookup::TryAgain`]): `EAI_AGAIN` / `WSATRY_AGAIN`.
    const AGAIN: c_int;
    /// A permanent failure ([`Lookup::Fail`]): `EAI_FAIL` / `WSANO_RECOVERY`.
    const FAIL: c_int;
    /// A known name with no address the hints accept.
    const NO_ADDRESS: c_int;
    /// Whether each of a name's addresses is asked for with `AI_NUMERICHOST` set.
    const DELEGATE_NUMERICHOST: bool;
    /// Whether an empty node is a name the resolver answers rather than one the OS reads.
    const EMPTY_NODE_IS_NAME: bool = false;
    /// Whether a host only `AI_NUMERICHOST` reads as an address (`127.1`) is a name otherwise, and
    /// a strict address is better asked of the OS with the caller's own hints.
    const SHORTHAND_IS_NAME: bool = false;
    /// Whether an IPv4 address asked for as `AF_INET6` with `AI_V4MAPPED` must be mapped here,
    /// because the OS refuses it with `AI_NUMERICHOST` set.
    const MAP_V4: bool = false;

    /// The original OS `getaddrinfo` of this flavour, bypassing the hook.
    ///
    /// # Safety
    /// As the OS function.
    unsafe fn getaddrinfo(
        node: *const Self::Char,
        service: *const Self::Char,
        hints: *const Self::Node,
        res: *mut *mut Self::Node,
    ) -> c_int;

    /// The original OS `freeaddrinfo` of this flavour, bypassing the hook.
    ///
    /// # Safety
    /// As the OS function.
    unsafe fn freeaddrinfo(list: *mut Self::Node);

    /// The node's `ai_flags`.
    fn flags(node: &Self::Node) -> c_int;
    /// Sets the node's `ai_flags`.
    fn set_flags(node: &mut Self::Node, flags: c_int);
    /// The node's `ai_family`.
    fn family(node: &Self::Node) -> c_int;

    /// The address of the node's `ai_next`.
    ///
    /// # Safety
    /// `node` is a live list node.
    unsafe fn next(node: *mut Self::Node) -> *mut *mut Self::Node;

    /// The address of the node's `ai_canonname`.
    ///
    /// # Safety
    /// `node` is a live list node.
    unsafe fn canonname(node: *mut Self::Node) -> *mut *mut Self::Char;

    /// `text` in this flavour's characters, NUL-terminated.
    fn encode(text: &str) -> Vec<Self::Char>;

    /// A NUL-terminated name as a `String`, invalid sequences replaced.
    ///
    /// # Safety
    /// `text` is NUL-terminated.
    unsafe fn decode(text: *const Self::Char) -> String;

    /// Allocates `name` as an `ai_canonname` for a joined list's head.
    fn canon_alloc(name: &str) -> *mut Self::Char;

    /// Frees a name from [`canon_alloc`](Flavor::canon_alloc).
    ///
    /// # Safety
    /// `name` came from [`canon_alloc`](Flavor::canon_alloc) and is freed once.
    unsafe fn canon_free(name: *mut Self::Char);

    /// Fails the call with `code` the way the OS does: returned as is on Unix; on Windows also
    /// stored with `WSASetLastError`.
    fn refuse(code: c_int) -> c_int {
        code
    }
}

/// What a resolver hook decided, before [`settle`] finishes the call.
pub(crate) enum Answer<T> {
    /// The call's result, final.
    Done(T),
    /// The resolver hands the name to the system resolver.
    Real,
}

/// Finishes a resolver hook: the resolver's answer, else the OS's own call, recorded as
/// unmodelled. A name the resolver hands to the system resolver is resolved in passthrough, so the
/// resolver's own sockets, files and timeouts reach the OS rather than the sim.
pub(crate) fn settle<T>(
    answer: Option<Answer<T>>,
    function: &'static str,
    call: impl FnOnce() -> T,
) -> T {
    match answer {
        Some(Answer::Done(value)) => value,
        Some(Answer::Real) => {
            domain::observe(function, None);
            let _passthrough = Passthrough::enter();
            call()
        }
        None => {
            domain::observe(function, None);
            call()
        }
    }
}

/// A list [`answer`] joined from several OS lists, remembered until it is freed.
struct Chain {
    /// Each OS-allocated piece of the list, as its first and last node.
    pieces: Vec<(usize, usize)>,
    /// The `ai_canonname` this module allocated on the head, or 0 if none.
    canon: usize,
}

/// Every joined list not yet freed, by head address. Lock only in passthrough; a poisoned lock is
/// recovered, since an entry is inserted or removed whole.
static CHAINS: Mutex<BTreeMap<usize, Chain>> = Mutex::new(BTreeMap::new());

/// A bitwise copy of the caller's hints, or the zeroed node a null `hints` stands for (POSIX
/// `freeaddrinfo` page: a null `hints` behaves as zero `ai_flags`, `ai_socktype` and
/// `ai_protocol` with `ai_family` `AF_UNSPEC`, which is 0; Microsoft Learn `getaddrinfo`:
/// `AF_UNSPEC` "and all other members set to zero").
///
/// # Safety
/// `hints` is null or a valid hints node.
unsafe fn copy_hints<F: Flavor>(hints: *const F::Node) -> F::Node {
    if hints.is_null() {
        // SAFETY: every flavour's node is plain integers and pointers, for which zero is valid.
        unsafe { mem::zeroed() }
    } else {
        // SAFETY: the caller's hints node, read bitwise; the copy owns nothing.
        unsafe { ptr::read(hints) }
    }
}

/// `getaddrinfo` against `resolver`. Called in passthrough.
///
/// The OS decides first whether `node` is a name at all. A null node (a service-only lookup) goes
/// straight to the OS. Otherwise the node is offered to the OS as a numeric host, with the
/// caller's hints plus `AI_NUMERICHOST` and without `AI_ADDRCONFIG`, so the probe asks only
/// whether the node is numeric. Any answer but `NONAME` is the call's answer, as is `NONAME` for
/// a caller that asked for `AI_NUMERICHOST` or for a strict address (a scope suffix such as
/// `%lo0` stripped). Only a node the OS refuses as numeric reaches the resolver. The flavour
/// constants adjust this for Windows:
///
/// - [`EMPTY_NODE_IS_NAME`](Flavor::EMPTY_NODE_IS_NAME): an empty node skips the probe.
/// - [`SHORTHAND_IS_NAME`](Flavor::SHORTHAND_IS_NAME): a strict address goes to the OS with the
///   caller's hints, and a shorthand the probe accepts (`127.1`) is still a name unless the
///   caller asked for `AI_NUMERICHOST`.
///
/// # Safety
/// The arguments are the caller's, as the OS function takes them.
pub(crate) unsafe fn getaddrinfo<F: Flavor>(
    resolver: &dyn Resolver,
    node: *const F::Char,
    service: *const F::Char,
    hints: *const F::Node,
    res: *mut *mut F::Node,
) -> Answer<c_int> {
    // SAFETY (whole function): the caller's pointers, passed on as given.
    unsafe {
        if node.is_null() {
            return Answer::Done(F::getaddrinfo(node, service, hints, res));
        }
        let name = F::decode(node);
        if !(F::EMPTY_NODE_IS_NAME && name.is_empty()) {
            let strict = {
                let addr = name.split_once('%').map_or(name.as_str(), |(addr, _)| addr);
                addr.parse::<IpAddr>().is_ok()
            };
            if strict && F::SHORTHAND_IS_NAME {
                return Answer::Done(F::getaddrinfo(node, service, hints, res));
            }
            let mut probe = copy_hints::<F>(hints);
            let flags = F::flags(&probe);
            F::set_flags(&mut probe, (flags | F::AI_NUMERICHOST) & !F::AI_ADDRCONFIG);
            let rc = F::getaddrinfo(node, service, &probe, res);
            let numeric = flags & F::AI_NUMERICHOST != 0;
            if rc == 0 && F::SHORTHAND_IS_NAME && !numeric {
                F::freeaddrinfo(*res);
                *res = ptr::null_mut();
            } else if rc != F::NONAME || numeric || strict {
                return Answer::Done(rc);
            }
        }
        match resolver.lookup(&name) {
            Lookup::NotFound => Answer::Done(F::refuse(F::NONAME)),
            Lookup::TryAgain => Answer::Done(F::refuse(F::AGAIN)),
            Lookup::Fail => Answer::Done(F::refuse(F::FAIL)),
            Lookup::Real => Answer::Real,
            Lookup::Addrs { canonical, addrs } => Answer::Done(answer::<F>(
                copy_hints::<F>(hints),
                service,
                &canonical,
                &addrs,
                res,
            )),
        }
    }
}

/// Builds the list for a known name from the OS's numeric answers, one address at a time.
///
/// Each address is asked with the caller's hints minus the canonical-name flags and
/// `AI_ADDRCONFIG`, plus `AI_NUMERICHOST` where
/// [`DELEGATE_NUMERICHOST`](Flavor::DELEGATE_NUMERICHOST), so family, socket type, protocol and
/// port filtering are the OS's own; an address the OS refuses is skipped. For `AF_INET6` the IPv6
/// addresses come first, and the IPv4 ones are asked only when no IPv6 address was accepted or
/// `AI_V4MAPPED` and `AI_ALL` are both set, as POSIX
/// specifies (IEEE Std 1003.1 `freeaddrinfo` page: `AI_V4MAPPED` returns mapped addresses "on
/// finding no matching IPv6 addresses"; with `AI_ALL`, "all matching IPv6 and IPv4 addresses").
/// No piece at all fails with [`NO_ADDRESS`](Flavor::NO_ADDRESS).
///
/// The pieces are linked tail to head. A list of one piece without a canonical name is the OS's
/// own and needs no record; anything else goes into [`CHAINS`].
unsafe fn answer<F: Flavor>(
    mut hints: F::Node,
    service: *const F::Char,
    canonical: &str,
    addrs: &[IpAddr],
    res: *mut *mut F::Node,
) -> c_int {
    let flags = F::flags(&hints);
    let numeric = if F::DELEGATE_NUMERICHOST {
        F::AI_NUMERICHOST
    } else {
        0
    };
    F::set_flags(
        &mut hints,
        (flags & !(F::AI_CANONICAL | F::AI_ADDRCONFIG)) | numeric,
    );
    let mut pieces = Vec::new();
    // SAFETY: `hints` is a valid node and `service` the caller's.
    let ask = |ip: &IpAddr, pieces: &mut Vec<(usize, usize)>| unsafe {
        piece::<F>(ip, service, &hints, pieces)
    };
    if F::family(&hints) == F::AF_INET6 {
        for ip in addrs.iter().filter(|ip| ip.is_ipv6()) {
            ask(ip, &mut pieces);
        }
        let both = flags & F::AI_V4MAPPED != 0 && flags & F::AI_ALL != 0;
        if pieces.is_empty() || both {
            for ip in addrs.iter().filter(|ip| ip.is_ipv4()) {
                match ip {
                    IpAddr::V4(v4) if F::MAP_V4 && flags & F::AI_V4MAPPED != 0 => {
                        ask(&IpAddr::V6(v4.to_ipv6_mapped()), &mut pieces)
                    }
                    _ => ask(ip, &mut pieces),
                }
            }
        }
    } else {
        for ip in addrs {
            ask(ip, &mut pieces);
        }
    }
    let Some(&(head, _)) = pieces.first() else {
        return F::refuse(F::NO_ADDRESS);
    };
    // SAFETY: every piece is a live list the OS just returned.
    unsafe {
        for pair in pieces.windows(2) {
            *F::next(pair[0].1 as *mut F::Node) = pair[1].0 as *mut F::Node;
        }
        let mut canon = 0;
        if flags & F::AI_CANONICAL != 0 {
            let name = F::canon_alloc(canonical);
            *F::canonname(head as *mut F::Node) = name;
            canon = name as usize;
        }
        if pieces.len() > 1 || canon != 0 {
            let _passthrough = Passthrough::enter();
            CHAINS
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(head, Chain { pieces, canon });
        }
        *res = head as *mut F::Node;
    }
    0
}

/// Asks the OS for `ip` as a numeric host, appending the list it returns to `pieces`. A refusal
/// (the address does not fit the hints) appends nothing.
unsafe fn piece<F: Flavor>(
    ip: &IpAddr,
    service: *const F::Char,
    hints: &F::Node,
    pieces: &mut Vec<(usize, usize)>,
) {
    let text = F::encode(&ip.to_string());
    let mut list = ptr::null_mut();
    // SAFETY: a NUL-terminated numeric host, the caller's service and valid hints.
    unsafe {
        if F::getaddrinfo(text.as_ptr(), service, hints, &mut list) != 0 || list.is_null() {
            return;
        }
        let mut tail = list;
        while !(*F::next(tail)).is_null() {
            tail = *F::next(tail);
        }
        pieces.push((list as usize, tail as usize));
    }
}

/// `freeaddrinfo` for any list, joined here or the OS's own, on any thread. A joined list still
/// [`intact`] has its canonical name freed and is cut at each piece's tail, so every piece goes
/// back to the OS exactly as the OS returned it.
///
/// # Safety
/// `list` is what the matching `getaddrinfo` returned, freed once.
pub(crate) unsafe fn freeaddrinfo<F: Flavor>(list: *mut F::Node) {
    let chain = {
        let _passthrough = Passthrough::enter();
        CHAINS
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(list as usize))
    };
    // SAFETY: a joined list is cut back into the OS's pieces before each is freed.
    unsafe {
        let Some(chain) = chain.filter(|chain| intact::<F>(list, chain)) else {
            return F::freeaddrinfo(list);
        };
        if chain.canon != 0 {
            *F::canonname(list) = ptr::null_mut();
            F::canon_free(chain.canon as *mut F::Char);
        }
        for &(_, tail) in &chain.pieces {
            *F::next(tail as *mut F::Node) = ptr::null_mut();
        }
        for &(head, _) in &chain.pieces {
            F::freeaddrinfo(head as *mut F::Node);
        }
    }
}

/// Whether `list` is still the list `chain` joined. A joined list freed through an unhooked
/// `freeaddrinfo` leaves its entry behind, and the allocator may hand its head to a later list of
/// the OS's own; cutting that one at the stale tails would corrupt the heap.
///
/// # Safety
/// `list` is a live list.
unsafe fn intact<F: Flavor>(list: *mut F::Node, chain: &Chain) -> bool {
    // SAFETY: only nodes reached from the caller's live list are read.
    unsafe {
        if chain.canon != 0 && *F::canonname(list) as usize != chain.canon {
            return false;
        }
        let mut node = list;
        for (index, &(head, tail)) in chain.pieces.iter().enumerate() {
            if node as usize != head {
                return false;
            }
            while node as usize != tail {
                if node.is_null() {
                    return false;
                }
                node = *F::next(node);
            }
            node = *F::next(node);
            let expected = chain.pieces.get(index + 1).map_or(0, |&(head, _)| head);
            if node as usize != expected {
                return false;
            }
        }
        true
    }
}

/// How many joined lists are waiting to be freed, process-wide. For leak tests.
#[doc(hidden)]
pub fn joined_lists() -> usize {
    let _passthrough = Passthrough::enter();
    CHAINS.lock().unwrap_or_else(|e| e.into_inner()).len()
}

/// `ip` with a v4-mapped IPv6 address (`::ffff:a.b.c.d`, RFC 4291 §2.5.5.2) unwrapped, as a
/// reverse lookup asks for it.
pub(crate) fn unmapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        v4 => v4,
    }
}
