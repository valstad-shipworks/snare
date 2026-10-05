//! Resolver hooks for Linux and macOS: `getaddrinfo`, `freeaddrinfo`, `getnameinfo` and
//! `gethostbyname` consult the calling thread's [`Resolver`](crate::Resolver) through
//! [`dispatch_resolver`], and finish through [`gai::settle`]. Forward lookups share the
//! [`gai`] algorithm over the [`Unix`] flavour. The other resolver entry points are observed
//! (recorded as unmodelled) and forwarded, so a test learns that its code resolved a name the
//! sim did not see.

use std::cell::RefCell;
use std::ffi::{CStr, CString, c_char, c_int};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::atomic::AtomicUsize;

use libc::{addrinfo, hostent, sockaddr, socklen_t};

use crate::domain::dispatch_resolver;
use crate::hooks::{Hook, hook, observed, original};
use crate::os::gai::{self, Answer, Flavor};
use crate::resolve::{Lookup, Reverse};

// Original addresses of the hooked resolver functions, filled when the hooks are installed.
static GETADDRINFO: AtomicUsize = AtomicUsize::new(0);
static FREEADDRINFO: AtomicUsize = AtomicUsize::new(0);
static GETNAMEINFO: AtomicUsize = AtomicUsize::new(0);
static GETHOSTBYNAME: AtomicUsize = AtomicUsize::new(0);

/// `getaddrinfo(3)`.
type GetAddrInfo = unsafe extern "C" fn(
    *const c_char,
    *const c_char,
    *const addrinfo,
    *mut *mut addrinfo,
) -> c_int;
/// `freeaddrinfo(3)`.
type FreeAddrInfo = unsafe extern "C" fn(*mut addrinfo);
/// `getnameinfo(3)`.
type GetNameInfo = unsafe extern "C" fn(
    *const sockaddr,
    socklen_t,
    *mut c_char,
    socklen_t,
    *mut c_char,
    socklen_t,
    c_int,
) -> c_int;
/// `gethostbyname(3)`.
type GetHostByName = unsafe extern "C" fn(*const c_char) -> *mut hostent;

// <netdb.h> h_errno values, the same on glibc (resolv/netdb.h) and Darwin (SDK <netdb.h>).
const HOST_NOT_FOUND: c_int = 1;
const TRY_AGAIN: c_int = 2;
const NO_RECOVERY: c_int = 3;
const NO_DATA: c_int = 4;

/// The resolver hooks. The `observed!` entries are entry points snare does not model, recorded
/// and forwarded: glibc's `__res_*` are what `res_init`/`res_query`/`res_search` name
/// (`<resolv.h>`: `#define res_init __res_init`), Darwin's `res_9_*` likewise (SDK `<resolv.h>`:
/// `#define res_init res_9_init`), `DNSServiceGetAddrInfo` is mDNSResponder's (`<dns_sd.h>`), and
/// `getaddrinfo_async_start` is Libinfo's Mach-port form (Libinfo
/// lookup.subproj/netdb_async.h).
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("getaddrinfo", getaddrinfo, GETADDRINFO),
        hook!("freeaddrinfo", freeaddrinfo, FREEADDRINFO),
        hook!("getnameinfo", getnameinfo, GETNAMEINFO),
        hook!("gethostbyname", gethostbyname, GETHOSTBYNAME),
        observed!("gethostbyname2", [name, family]),
        observed!("gethostbyaddr", [address, length, family]),
        #[cfg(target_os = "linux")]
        observed!(
            "gethostbyname_r",
            [name, result, buffer, length, out, error]
        ),
        #[cfg(target_os = "linux")]
        observed!(
            "gethostbyname2_r",
            [name, family, result, buffer, length, out, error]
        ),
        #[cfg(target_os = "linux")]
        observed!("getaddrinfo_a", [mode, list, count, event]),
        #[cfg(target_os = "linux")]
        observed!("__res_init", []),
        #[cfg(target_os = "linux")]
        observed!("__res_query", [name, class, kind, answer, length]),
        #[cfg(target_os = "linux")]
        observed!("__res_search", [name, class, kind, answer, length]),
        #[cfg(target_os = "macos")]
        observed!("res_9_init", []),
        #[cfg(target_os = "macos")]
        observed!("res_9_query", [name, class, kind, answer, length]),
        #[cfg(target_os = "macos")]
        observed!("res_9_search", [name, class, kind, answer, length]),
        #[cfg(target_os = "macos")]
        observed!(
            "DNSServiceGetAddrInfo",
            [
                reference, flags, interface, protocol, name, callback, context
            ]
        ),
        #[cfg(target_os = "macos")]
        observed!(
            "getaddrinfo_async_start",
            [port, node, service, hints, callback, context]
        ),
    ]
}

/// The `addrinfo` flavour of [`gai`] on Linux and macOS.
struct Unix;

impl Flavor for Unix {
    type Node = addrinfo;
    type Char = c_char;

    const AF_INET6: c_int = libc::AF_INET6;
    const AI_NUMERICHOST: c_int = libc::AI_NUMERICHOST;
    const AI_CANONICAL: c_int = libc::AI_CANONNAME;
    const AI_ADDRCONFIG: c_int = libc::AI_ADDRCONFIG;
    const AI_V4MAPPED: c_int = libc::AI_V4MAPPED;
    const AI_ALL: c_int = libc::AI_ALL;
    const NONAME: c_int = libc::EAI_NONAME;
    const AGAIN: c_int = libc::EAI_AGAIN;
    const FAIL: c_int = libc::EAI_FAIL;
    // Measured: glibc and Darwin fail a hosts-file name with no address of the asked family with
    // EAI_NONAME, not EAI_NODATA (snare tests/dns.rs family_mismatch_is_eai_noname, which asks the
    // real resolver on both: glibc with AF_INET for an IPv6-only name, Darwin with AF_INET6 and
    // AI_ADDRCONFIG for an IPv4-only one, since without AI_ADDRCONFIG Darwin answers the
    // v4-mapped form instead).
    const NO_ADDRESS: c_int = libc::EAI_NONAME;
    // Measured on macOS 26: Darwin answers an IPv4 host asked as AF_INET6 with its v4-mapped form
    // even without AI_V4MAPPED, as it does for a v4-only name, except that with AI_NUMERICHOST set
    // it maps only under AI_V4MAPPED and otherwise fails EAI_NONAME. Asking without
    // AI_NUMERICHOST keeps the name's behaviour; snare tests/dns.rs v4mapped_rules pins the
    // sim's answer (::ffff:a.b.c.d for a v4-only name without AI_V4MAPPED).
    const DELEGATE_NUMERICHOST: bool = cfg!(not(target_os = "macos"));

    unsafe fn getaddrinfo(
        node: *const c_char,
        service: *const c_char,
        hints: *const addrinfo,
        res: *mut *mut addrinfo,
    ) -> c_int {
        // SAFETY: the original getaddrinfo, with the caller's arguments.
        unsafe { original::<GetAddrInfo>(&GETADDRINFO)(node, service, hints, res) }
    }

    unsafe fn freeaddrinfo(list: *mut addrinfo) {
        // SAFETY: a list the original getaddrinfo returned.
        unsafe { original::<FreeAddrInfo>(&FREEADDRINFO)(list) }
    }

    fn flags(node: &addrinfo) -> c_int {
        node.ai_flags
    }

    fn set_flags(node: &mut addrinfo, flags: c_int) {
        node.ai_flags = flags;
    }

    fn family(node: &addrinfo) -> c_int {
        node.ai_family
    }

    unsafe fn next(node: *mut addrinfo) -> *mut *mut addrinfo {
        // SAFETY: the caller's live node.
        unsafe { &raw mut (*node).ai_next }
    }

    unsafe fn canonname(node: *mut addrinfo) -> *mut *mut c_char {
        // SAFETY: the caller's live node.
        unsafe { &raw mut (*node).ai_canonname }
    }

    fn encode(text: &str) -> Vec<c_char> {
        text.bytes().map(|b| b as c_char).chain([0]).collect()
    }

    unsafe fn decode(text: *const c_char) -> String {
        // SAFETY: the caller's NUL-terminated string.
        unsafe { CStr::from_ptr(text) }
            .to_string_lossy()
            .into_owned()
    }

    /// `strdup`, because the OS's `freeaddrinfo` frees `ai_canonname` with `free` (glibc
    /// nss/getaddrinfo.c `freeaddrinfo`; Darwin Libinfo lookup.subproj/si_getaddrinfo.c).
    fn canon_alloc(name: &str) -> *mut c_char {
        let name = CString::new(name.replace('\0', "")).unwrap_or_default();
        // SAFETY: a NUL-terminated string; strdup allocates as the OS's own canonname is, so a
        // list freed through an unhooked freeaddrinfo still frees it correctly.
        unsafe { libc::strdup(name.as_ptr()) }
    }

    unsafe fn canon_free(name: *mut c_char) {
        // SAFETY: allocated by strdup in canon_alloc.
        unsafe { libc::free(name.cast()) }
    }
}

/// Hook for `getaddrinfo(3)`: the [`gai`] algorithm against the domain's resolver.
unsafe extern "C" fn getaddrinfo(
    node: *const c_char,
    service: *const c_char,
    hints: *const addrinfo,
    res: *mut *mut addrinfo,
) -> c_int {
    // SAFETY: the caller's arguments, as getaddrinfo(3) takes them.
    let answer = dispatch_resolver(|resolver| unsafe {
        gai::getaddrinfo::<Unix>(resolver, node, service, hints, res)
    });
    // SAFETY: as above.
    gai::settle(answer, "getaddrinfo", || unsafe {
        Unix::getaddrinfo(node, service, hints, res)
    })
}

/// Hook for `freeaddrinfo(3)`, for joined lists and the OS's own alike.
unsafe extern "C" fn freeaddrinfo(list: *mut addrinfo) {
    // SAFETY: what getaddrinfo returned, freed once by the caller.
    unsafe { gai::freeaddrinfo::<Unix>(list) }
}

/// The IP address in `address`, if it is an IPv4 or IPv6 socket address.
///
/// # Safety
/// `address` is null or points at `length` readable bytes.
unsafe fn socket_ip(address: *const sockaddr, length: socklen_t) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    let length = length as usize;
    // SAFETY: the family and the address structure are read only within `length`.
    unsafe {
        match c_int::from((*address).sa_family) {
            libc::AF_INET if length >= size_of::<libc::sockaddr_in>() => {
                let v4 = &*address.cast::<libc::sockaddr_in>();
                Some(IpAddr::V4(Ipv4Addr::from(u32::from_be(v4.sin_addr.s_addr))))
            }
            libc::AF_INET6 if length >= size_of::<libc::sockaddr_in6>() => {
                let v6 = &*address.cast::<libc::sockaddr_in6>();
                Some(IpAddr::V6(Ipv6Addr::from(v6.sin6_addr.s6_addr)))
            }
            _ => None,
        }
    }
}

/// Hook for `getnameinfo(3)`. Only the host part is the resolver's; the service is always the
/// OS's, asked with a null host buffer when the caller wants one.
///
/// The OS answers outright when no host is wanted, when `NI_NUMERICHOST` is set, or when the
/// address is not IPv4/IPv6. A name the resolver does not know fails with `EAI_NONAME` under
/// `NI_NAMEREQD` and is otherwise the numeric form, which the OS produces; a known name that
/// does not fit with its NUL fails with `EAI_OVERFLOW` (IEEE Std 1003.1 `getnameinfo`: "If the
/// flag bit NI_NAMEREQD is set, an error shall be returned if the host's name cannot be located";
/// otherwise "the numeric form of the address ... is returned"; `EAI_OVERFLOW`: "An argument
/// buffer overflowed").
unsafe extern "C" fn getnameinfo(
    address: *const sockaddr,
    length: socklen_t,
    host: *mut c_char,
    host_length: socklen_t,
    service: *mut c_char,
    service_length: socklen_t,
    flags: c_int,
) -> c_int {
    // SAFETY: the caller's arguments, with the host buffer left out or the flags changed.
    let call = |host: *mut c_char, host_length: socklen_t, flags: c_int| unsafe {
        original::<GetNameInfo>(&GETNAMEINFO)(
            address,
            length,
            host,
            host_length,
            service,
            service_length,
            flags,
        )
    };
    let answer = dispatch_resolver(|resolver| {
        if host.is_null() || host_length == 0 || flags & libc::NI_NUMERICHOST != 0 {
            return Answer::Done(call(host, host_length, flags));
        }
        // SAFETY: the caller's socket address of `length` bytes.
        let Some(ip) = (unsafe { socket_ip(address, length) }) else {
            return Answer::Done(call(host, host_length, flags));
        };
        match resolver.reverse(gai::unmapped(ip)) {
            Reverse::Real => Answer::Real,
            Reverse::NotFound if flags & libc::NI_NAMEREQD != 0 => Answer::Done(libc::EAI_NONAME),
            Reverse::NotFound => {
                Answer::Done(call(host, host_length, flags | libc::NI_NUMERICHOST))
            }
            Reverse::Name(name) => {
                if name.len() >= host_length as usize {
                    return Answer::Done(libc::EAI_OVERFLOW);
                }
                if !service.is_null() && service_length > 0 {
                    let rc = call(ptr::null_mut(), 0, flags);
                    if rc != 0 {
                        return Answer::Done(rc);
                    }
                }
                // SAFETY: `host` holds `host_length` bytes, more than the name and its NUL.
                unsafe {
                    ptr::copy_nonoverlapping(name.as_ptr(), host.cast::<u8>(), name.len());
                    *host.add(name.len()) = 0;
                }
                Answer::Done(0)
            }
        }
    });
    gai::settle(answer, "getnameinfo", || call(host, host_length, flags))
}

/// The storage a `gethostbyname` answer points into, one per thread, as the OS keeps its own.
/// `entry` points into the other fields, so the buffer is boxed and never moved once built.
struct HostBuffer {
    /// `h_name`.
    _name: CString,
    /// The IPv4 addresses `h_addr_list` points at, in network byte order.
    _addrs: Vec<[u8; 4]>,
    /// `h_addr_list`, NULL-terminated.
    _list: Vec<*mut c_char>,
    /// `h_aliases`: no aliases, just the terminating NULL.
    _aliases: Box<[*mut c_char; 1]>,
    entry: hostent,
}

thread_local! {
    /// The calling thread's last `gethostbyname` answer. Replacing it invalidates the previous
    /// `hostent`, which man 3 gethostbyname (NOTES) allows: the call may return pointers to
    /// static data that later calls overwrite.
    static HOSTENT: RefCell<Option<Box<HostBuffer>>> = const { RefCell::new(None) };
}

/// Builds an `AF_INET` `hostent` (`h_length` 4) for `name` with `addrs`, stores it in this
/// thread's [`HOSTENT`], and returns a pointer to it valid until the thread's next answer.
fn host_entry(name: &str, addrs: Vec<[u8; 4]>) -> *mut hostent {
    let name = CString::new(name.replace('\0', "")).unwrap_or_default();
    let mut addrs = addrs;
    let mut list: Vec<*mut c_char> = addrs
        .iter_mut()
        .map(|a| a.as_mut_ptr().cast())
        .chain([ptr::null_mut()])
        .collect();
    let mut aliases = Box::new([ptr::null_mut()]);
    let entry = hostent {
        h_name: name.as_ptr().cast_mut(),
        h_aliases: aliases.as_mut_ptr(),
        h_addrtype: libc::AF_INET,
        h_length: 4,
        h_addr_list: list.as_mut_ptr(),
    };
    let mut buffer = Box::new(HostBuffer {
        _name: name,
        _addrs: addrs,
        _list: list,
        _aliases: aliases,
        entry,
    });
    let entry = &raw mut buffer.entry;
    HOSTENT.with_borrow_mut(|slot| *slot = Some(buffer));
    entry
}

/// Sets glibc's per-thread `h_errno` (resolv/netdb.h: `#define h_errno (*__h_errno_location ())`).
#[cfg(target_os = "linux")]
fn set_h_errno(code: c_int) {
    unsafe extern "C" {
        fn __h_errno_location() -> *mut c_int;
    }
    // SAFETY: glibc's per-thread h_errno.
    unsafe { *__h_errno_location() = code };
}

/// Sets Darwin's `h_errno`, a plain exported `int` (SDK `<netdb.h>`: `extern int h_errno;`),
/// found once by `dlsym` since the `libc` crate does not declare it.
#[cfg(target_os = "macos")]
fn set_h_errno(code: c_int) {
    static H_ERRNO: crate::race::RaceCell<usize> = crate::race::RaceCell::new();
    // SAFETY: looks up libsystem_info's exported `h_errno` int.
    let address = *H_ERRNO
        .get_or_init(|| unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"h_errno".as_ptr()) } as usize)
        .0;
    if address != 0 {
        // SAFETY: the address of the `int h_errno` global.
        unsafe { *(address as *mut c_int) = code };
    }
}

/// Fails `gethostbyname` with h_errno `code`: NULL with `h_errno` set.
fn host_failure(code: c_int) -> *mut hostent {
    set_h_errno(code);
    ptr::null_mut()
}

/// Whether the OS reads `name` as a numeric host.
///
/// # Safety
/// `name` is NUL-terminated.
unsafe fn numeric(name: *const c_char) -> bool {
    // SAFETY: zero is a valid addrinfo.
    let mut hints: addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = libc::AI_NUMERICHOST;
    let mut list = ptr::null_mut();
    // SAFETY: the caller's name and a valid hints node.
    let rc = unsafe { Unix::getaddrinfo(name, ptr::null(), &hints, &mut list) };
    if rc == 0 && !list.is_null() {
        // SAFETY: the list just returned.
        unsafe { Unix::freeaddrinfo(list) };
    }
    rc == 0
}

/// Hook for `gethostbyname(3)`. A numeric host is the OS's. A known name answers with its IPv4
/// addresses only, as the call is `AF_INET`-only (man 3 gethostbyname); one with none fails with
/// `NO_DATA`, which the page defines as a valid name without an IP address. Resolver failures map
/// to `HOST_NOT_FOUND`, `TRY_AGAIN` and `NO_RECOVERY`.
unsafe extern "C" fn gethostbyname(name: *const c_char) -> *mut hostent {
    // SAFETY: the caller's name.
    let call = || unsafe { original::<GetHostByName>(&GETHOSTBYNAME)(name) };
    let answer = dispatch_resolver(|resolver| {
        // SAFETY: the caller's NUL-terminated name.
        if name.is_null() || unsafe { numeric(name) } {
            return Answer::Done(call());
        }
        // SAFETY: as above.
        let text = unsafe { Unix::decode(name) };
        Answer::Done(match resolver.lookup(&text) {
            Lookup::Real => return Answer::Real,
            Lookup::NotFound => host_failure(HOST_NOT_FOUND),
            Lookup::TryAgain => host_failure(TRY_AGAIN),
            Lookup::Fail => host_failure(NO_RECOVERY),
            Lookup::Addrs { canonical, addrs } => {
                let v4: Vec<[u8; 4]> = addrs
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(v4.octets()),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
                if v4.is_empty() {
                    host_failure(NO_DATA)
                } else {
                    host_entry(&canonical, v4)
                }
            }
        })
    });
    gai::settle(answer, "gethostbyname", call)
}
