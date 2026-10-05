//! Winsock resolver hooks: `getaddrinfo`/`GetAddrInfoW`, their frees, `getnameinfo`/
//! `GetNameInfoW` and `gethostbyname` (all `ws2_32.dll`) consult the calling thread's
//! [`Resolver`] and finish through [`gai::settle`]. Forward lookups share the [`gai`] algorithm
//! over the [`Ansi`] and [`Wide`] flavours. Failures are Winsock codes, returned and also stored
//! with `WSASetLastError`, which the Winsock docs recommend reading
//! ([Microsoft Learn: getaddrinfo](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo)).
//! The other resolver entry points (`GetAddrInfoEx*`, `gethostbyaddr`, `WSAAsyncGetHostByName`,
//! `DnsQuery_W`, `DnsQueryEx`) are observed and forwarded.

use std::cell::RefCell;
use std::ffi::{CString, c_int};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::sync::atomic::AtomicUsize;

use windows_sys::Win32::Networking::WinSock::{
    ADDRINFOA, ADDRINFOW, AF_INET, AF_INET6, AI_ADDRCONFIG, AI_ALL, AI_CANONNAME, AI_FQDN,
    AI_NUMERICHOST, AI_V4MAPPED, HOSTENT, NI_NAMEREQD, NI_NUMERICHOST, SOCKADDR, WSAEFAULT,
    WSAHOST_NOT_FOUND, WSANO_DATA, WSANO_RECOVERY, WSASetLastError, WSATRY_AGAIN,
};

use crate::domain::dispatch_resolver;
use crate::hooks::{Hook, hook, observed, original};
use crate::os::gai::{self, Answer, Flavor};
use crate::resolve::{Lookup, Resolver, Reverse};

// Original addresses of the hooked resolver functions, filled when the hooks are installed.
static GETADDRINFO: AtomicUsize = AtomicUsize::new(0);
static FREEADDRINFO: AtomicUsize = AtomicUsize::new(0);
static GETADDRINFOW: AtomicUsize = AtomicUsize::new(0);
static FREEADDRINFOW: AtomicUsize = AtomicUsize::new(0);
static GETNAMEINFO: AtomicUsize = AtomicUsize::new(0);
static GETNAMEINFOW: AtomicUsize = AtomicUsize::new(0);
static GETHOSTBYNAME: AtomicUsize = AtomicUsize::new(0);

/// `getaddrinfo` (`GetAddrInfoA`).
type GetAddrInfoA =
    unsafe extern "system" fn(*const u8, *const u8, *const ADDRINFOA, *mut *mut ADDRINFOA) -> i32;
/// `freeaddrinfo`.
type FreeAddrInfoA = unsafe extern "system" fn(*mut ADDRINFOA);
/// `GetAddrInfoW`.
type GetAddrInfoW =
    unsafe extern "system" fn(*const u16, *const u16, *const ADDRINFOW, *mut *mut ADDRINFOW) -> i32;
/// `FreeAddrInfoW`.
type FreeAddrInfoW = unsafe extern "system" fn(*mut ADDRINFOW);
/// `getnameinfo` (`C` = `u8`) or `GetNameInfoW` (`C` = `u16`); the buffer sizes are `DWORD`s
/// counting characters.
type GetNameInfo<C> =
    unsafe extern "system" fn(*const SOCKADDR, i32, *mut C, u32, *mut C, u32, i32) -> i32;
/// `gethostbyname`.
type GetHostByName = unsafe extern "system" fn(*const u8) -> *mut HOSTENT;

/// The Winsock resolver hooks, each in `ws2_32.dll` (`DnsQuery_W`/`DnsQueryEx` in `dnsapi.dll`).
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!("getaddrinfo", "ws2_32.dll", getaddrinfo, GETADDRINFO),
        hook!("freeaddrinfo", "ws2_32.dll", freeaddrinfo, FREEADDRINFO),
        hook!("GetAddrInfoW", "ws2_32.dll", get_addr_info_w, GETADDRINFOW),
        hook!(
            "FreeAddrInfoW",
            "ws2_32.dll",
            free_addr_info_w,
            FREEADDRINFOW
        ),
        hook!("getnameinfo", "ws2_32.dll", getnameinfo, GETNAMEINFO),
        hook!("GetNameInfoW", "ws2_32.dll", get_name_info_w, GETNAMEINFOW),
        hook!("gethostbyname", "ws2_32.dll", gethostbyname, GETHOSTBYNAME),
        observed!("GetAddrInfoExW" in "ws2_32.dll", [name, service, namespace, provider, hints, result, timeout, overlapped, routine, handle]),
        observed!("GetAddrInfoExA" in "ws2_32.dll", [name, service, namespace, provider, hints, result, timeout, overlapped, routine, handle]),
        observed!("gethostbyaddr" in "ws2_32.dll", [address, length, family]),
        observed!("WSAAsyncGetHostByName" in "ws2_32.dll", [window, message, name, buffer, length]),
        observed!("DnsQuery_W" in "dnsapi.dll", [name, kind, options, extra, results, reserved]),
        observed!("DnsQueryEx" in "dnsapi.dll", [request, result, cancel]),
    ]
}

/// Defines one Winsock [`Flavor`]: `$flavor` over node `$node` and characters `$char`, calling
/// the originals in slots `$get`/`$free` of types `$get_ty`/`$free_ty`.
///
/// The constants follow [Microsoft Learn: getaddrinfo](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getaddrinfo):
/// `EAI_NONAME`, `EAI_AGAIN` and `EAI_FAIL` are `WSAHOST_NOT_FOUND`, `WSATRY_AGAIN` and
/// `WSANO_RECOVERY`; `WSANO_DATA` is "the requested name is valid, but no data of the requested
/// type was found"; `AI_FQDN` as well as `AI_CANONNAME` fills `ai_canonname`; and an empty node
/// asks for "all registered addresses on the local computer". In snare's tests/dns_win.rs,
/// `SHORTHAND_IS_NAME` (`127.1`) is checked against the real Winsock by
/// `numeric_passthrough_matches_os`, and `MAP_V4` by `v4mapped_rules`; `NO_ADDRESS` (in
/// `v4mapped_rules`) and `EMPTY_NODE_IS_NAME` (in `empty_node_is_local_host`) rest on the page
/// above, and those tests pin only the sim's answer.
macro_rules! flavor {
    ($flavor:ident, $node:ty, $char:ty, $get:ident, $free:ident, $get_ty:ty, $free_ty:ty) => {
        struct $flavor;

        impl Flavor for $flavor {
            type Node = $node;
            type Char = $char;

            const AF_INET6: c_int = AF_INET6 as c_int;
            const AI_NUMERICHOST: c_int = AI_NUMERICHOST as c_int;
            const AI_CANONICAL: c_int = (AI_CANONNAME | AI_FQDN) as c_int;
            const AI_ADDRCONFIG: c_int = AI_ADDRCONFIG as c_int;
            const AI_V4MAPPED: c_int = AI_V4MAPPED as c_int;
            const AI_ALL: c_int = AI_ALL as c_int;
            const NONAME: c_int = WSAHOST_NOT_FOUND;
            const AGAIN: c_int = WSATRY_AGAIN;
            const FAIL: c_int = WSANO_RECOVERY;
            const NO_ADDRESS: c_int = WSANO_DATA;
            const DELEGATE_NUMERICHOST: bool = true;
            const EMPTY_NODE_IS_NAME: bool = true;
            const SHORTHAND_IS_NAME: bool = true;
            const MAP_V4: bool = true;

            unsafe fn getaddrinfo(
                node: *const $char,
                service: *const $char,
                hints: *const $node,
                res: *mut *mut $node,
            ) -> c_int {
                // SAFETY: the original function, with the caller's arguments.
                unsafe { original::<$get_ty>(&$get)(node, service, hints, res) }
            }

            unsafe fn freeaddrinfo(list: *mut $node) {
                // SAFETY: a list the original function returned.
                unsafe { original::<$free_ty>(&$free)(list) }
            }

            fn flags(node: &$node) -> c_int {
                node.ai_flags
            }

            fn set_flags(node: &mut $node, flags: c_int) {
                node.ai_flags = flags;
            }

            fn family(node: &$node) -> c_int {
                node.ai_family
            }

            unsafe fn next(node: *mut $node) -> *mut *mut $node {
                // SAFETY: the caller's live node.
                unsafe { &raw mut (*node).ai_next }
            }

            unsafe fn canonname(node: *mut $node) -> *mut *mut $char {
                // SAFETY: the caller's live node.
                unsafe { &raw mut (*node).ai_canonname }
            }

            fn encode(text: &str) -> Vec<$char> {
                <$flavor as Text>::encode(text)
            }

            unsafe fn decode(text: *const $char) -> String {
                // SAFETY: the caller's NUL-terminated string.
                unsafe { <$flavor as Text>::decode(text) }
            }

            /// A boxed slice of the name and its NUL. Not Winsock's allocation, so only the hooked
            /// free releases it: [`gai::freeaddrinfo`] clears `ai_canonname` before handing the
            /// pieces back to Winsock.
            fn canon_alloc(name: &str) -> *mut $char {
                Box::into_raw(<Self as Text>::encode(name).into_boxed_slice()).cast()
            }

            /// Rebuilds the boxed slice from the name's length up to and including its NUL.
            unsafe fn canon_free(name: *mut $char) {
                // SAFETY: from canon_alloc: a boxed slice of the name and its NUL.
                unsafe {
                    let mut len = 0;
                    while *name.add(len) != 0 {
                        len += 1;
                    }
                    drop(Box::from_raw(ptr::slice_from_raw_parts_mut(name, len + 1)));
                }
            }

            fn refuse(code: c_int) -> c_int {
                // SAFETY: sets the calling thread's Winsock error.
                unsafe { WSASetLastError(code) };
                code
            }
        }
    };
}

/// NUL-terminated text in one character width.
trait Text {
    type Char: Copy;
    /// `text` NUL-terminated, interior NULs dropped.
    fn encode(text: &str) -> Vec<Self::Char>;
    /// A NUL-terminated string as a `String`, invalid sequences replaced.
    ///
    /// # Safety
    /// `text` is NUL-terminated.
    unsafe fn decode(text: *const Self::Char) -> String;
}

// `getaddrinfo`/`freeaddrinfo` over `ADDRINFOA` and byte strings.
flavor!(
    Ansi,
    ADDRINFOA,
    u8,
    GETADDRINFO,
    FREEADDRINFO,
    GetAddrInfoA,
    FreeAddrInfoA
);
// `GetAddrInfoW`/`FreeAddrInfoW` over `ADDRINFOW` and UTF-16 strings.
flavor!(
    Wide,
    ADDRINFOW,
    u16,
    GETADDRINFOW,
    FREEADDRINFOW,
    GetAddrInfoW,
    FreeAddrInfoW
);

impl Text for Ansi {
    type Char = u8;

    fn encode(text: &str) -> Vec<u8> {
        text.bytes().filter(|&b| b != 0).chain([0]).collect()
    }

    unsafe fn decode(text: *const u8) -> String {
        // SAFETY: the caller's NUL-terminated string.
        unsafe { std::ffi::CStr::from_ptr(text.cast()) }
            .to_string_lossy()
            .into_owned()
    }
}

impl Text for Wide {
    type Char = u16;

    fn encode(text: &str) -> Vec<u16> {
        text.encode_utf16().filter(|&c| c != 0).chain([0]).collect()
    }

    unsafe fn decode(text: *const u16) -> String {
        // SAFETY: the caller's NUL-terminated string.
        unsafe {
            let mut len = 0;
            while *text.add(len) != 0 {
                len += 1;
            }
            String::from_utf16_lossy(std::slice::from_raw_parts(text, len))
        }
    }
}

/// The hook body every `getaddrinfo` flavour shares.
///
/// # Safety
/// The caller's arguments, as the OS function takes them.
unsafe fn lookup<F: Flavor>(
    name: &'static str,
    node: *const F::Char,
    service: *const F::Char,
    hints: *const F::Node,
    res: *mut *mut F::Node,
) -> i32 {
    // SAFETY: as the caller's.
    let answer = dispatch_resolver(|resolver| unsafe {
        gai::getaddrinfo::<F>(resolver, node, service, hints, res)
    });
    // SAFETY: as the caller's.
    gai::settle(answer, name, || unsafe {
        F::getaddrinfo(node, service, hints, res)
    })
}

/// Hook for `getaddrinfo` (ANSI).
unsafe extern "system" fn getaddrinfo(
    node: *const u8,
    service: *const u8,
    hints: *const ADDRINFOA,
    res: *mut *mut ADDRINFOA,
) -> i32 {
    // SAFETY: the caller's arguments.
    unsafe { lookup::<Ansi>("getaddrinfo", node, service, hints, res) }
}

/// Hook for `GetAddrInfoW`.
unsafe extern "system" fn get_addr_info_w(
    node: *const u16,
    service: *const u16,
    hints: *const ADDRINFOW,
    res: *mut *mut ADDRINFOW,
) -> i32 {
    // SAFETY: the caller's arguments.
    unsafe { lookup::<Wide>("GetAddrInfoW", node, service, hints, res) }
}

/// Hook for `freeaddrinfo`.
unsafe extern "system" fn freeaddrinfo(list: *mut ADDRINFOA) {
    // SAFETY: what getaddrinfo returned, freed once by the caller.
    unsafe { gai::freeaddrinfo::<Ansi>(list) }
}

/// Hook for `FreeAddrInfoW`.
unsafe extern "system" fn free_addr_info_w(list: *mut ADDRINFOW) {
    // SAFETY: what GetAddrInfoW returned, freed once by the caller.
    unsafe { gai::freeaddrinfo::<Wide>(list) }
}

/// The IP address in `address`, if it is an IPv4 or IPv6 socket address.
///
/// # Safety
/// `address` is null or points at `length` readable bytes.
unsafe fn socket_ip(address: *const SOCKADDR, length: i32) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    let bytes = address.cast::<u8>();
    let length = length.max(0) as usize;
    // SAFETY: SOCKADDR_IN holds the address at bytes 4..8 of 16, SOCKADDR_IN6 at 8..24 of 28
    // (ws2def.h `SOCKADDR_IN`: family, port, `IN_ADDR`, 8 zero bytes; ws2ipdef.h `SOCKADDR_IN6_LH`:
    // family, port, flowinfo, `IN6_ADDR`, scope id); each is read only within `length`.
    unsafe {
        match (*address).sa_family {
            AF_INET if length >= 16 => {
                let mut octets = [0u8; 4];
                ptr::copy_nonoverlapping(bytes.add(4), octets.as_mut_ptr(), 4);
                Some(IpAddr::V4(Ipv4Addr::from(octets)))
            }
            AF_INET6 if length >= 28 => {
                let mut octets = [0u8; 16];
                ptr::copy_nonoverlapping(bytes.add(8), octets.as_mut_ptr(), 16);
                Some(IpAddr::V6(Ipv6Addr::from(octets)))
            }
            _ => None,
        }
    }
}

/// The hook body both `getnameinfo` widths share; `buffer` sizes count characters.
///
/// As the Unix hook, only the host part is the resolver's and the service is Winsock's. An
/// unknown name fails with `WSAHOST_NOT_FOUND` under `NI_NAMEREQD` and is otherwise the numeric
/// form ([Microsoft Learn: getnameinfo](https://learn.microsoft.com/en-us/windows/win32/api/ws2tcpip/nf-ws2tcpip-getnameinfo):
/// `EAI_NONAME` is `WSAHOST_NOT_FOUND`, "NI_NAMEREQD is set and the host name cannot be
/// located"). A known name that does not fit with its NUL fails with `WSAEFAULT`. That is snare's
/// choice: the page documents `WSAEFAULT` only for a bad `sa`/`salen`, and snare tests/dns_win.rs
/// `getnameinfo_reverse` pins the sim's answer without comparing it to Winsock's.
///
/// # Safety
/// The caller's arguments, as the OS function takes them.
#[allow(clippy::too_many_arguments)]
unsafe fn name_info<F: Flavor>(
    function: &'static str,
    slot: &AtomicUsize,
    address: *const SOCKADDR,
    length: i32,
    host: *mut F::Char,
    host_length: u32,
    service: *mut F::Char,
    service_length: u32,
    flags: i32,
) -> i32 {
    // SAFETY: the original function, with the caller's arguments, the host buffer left out or
    // the flags changed.
    let call = |host: *mut F::Char, host_length: u32, flags: i32| unsafe {
        original::<GetNameInfo<F::Char>>(slot)(
            address,
            length,
            host,
            host_length,
            service,
            service_length,
            flags,
        )
    };
    let answer = dispatch_resolver(|resolver: &dyn Resolver| {
        if host.is_null() || host_length == 0 || flags & NI_NUMERICHOST as i32 != 0 {
            return Answer::Done(call(host, host_length, flags));
        }
        // SAFETY: the caller's socket address of `length` bytes.
        let Some(ip) = (unsafe { socket_ip(address, length) }) else {
            return Answer::Done(call(host, host_length, flags));
        };
        match resolver.reverse(gai::unmapped(ip)) {
            Reverse::Real => Answer::Real,
            Reverse::NotFound if flags & NI_NAMEREQD as i32 != 0 => {
                Answer::Done(F::refuse(WSAHOST_NOT_FOUND))
            }
            Reverse::NotFound => {
                Answer::Done(call(host, host_length, flags | NI_NUMERICHOST as i32))
            }
            Reverse::Name(name) => {
                let text = F::encode(&name);
                if text.len() > host_length as usize {
                    return Answer::Done(F::refuse(WSAEFAULT));
                }
                if !service.is_null() && service_length > 0 {
                    let rc = call(ptr::null_mut(), 0, flags);
                    if rc != 0 {
                        return Answer::Done(rc);
                    }
                }
                // SAFETY: `host` holds `host_length` characters, at least the name and its NUL.
                unsafe { ptr::copy_nonoverlapping(text.as_ptr(), host, text.len()) };
                Answer::Done(0)
            }
        }
    });
    gai::settle(answer, function, || call(host, host_length, flags))
}

/// Hook for `getnameinfo` (ANSI).
unsafe extern "system" fn getnameinfo(
    address: *const SOCKADDR,
    length: i32,
    host: *mut u8,
    host_length: u32,
    service: *mut u8,
    service_length: u32,
    flags: i32,
) -> i32 {
    // SAFETY: the caller's arguments.
    unsafe {
        name_info::<Ansi>(
            "getnameinfo",
            &GETNAMEINFO,
            address,
            length,
            host,
            host_length,
            service,
            service_length,
            flags,
        )
    }
}

/// Hook for `GetNameInfoW`.
unsafe extern "system" fn get_name_info_w(
    address: *const SOCKADDR,
    length: i32,
    host: *mut u16,
    host_length: u32,
    service: *mut u16,
    service_length: u32,
    flags: i32,
) -> i32 {
    // SAFETY: the caller's arguments.
    unsafe {
        name_info::<Wide>(
            "GetNameInfoW",
            &GETNAMEINFOW,
            address,
            length,
            host,
            host_length,
            service,
            service_length,
            flags,
        )
    }
}

/// The storage a `gethostbyname` answer points into, one per thread, as Winsock keeps its own
/// ([Microsoft Learn: gethostbyname](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-gethostbyname):
/// "allocated internally by the Winsock DLL from thread local storage. Only a single hostent
/// structure is allocated and used"). `entry` points into the other fields, so the buffer is
/// boxed and never moved once built.
struct HostBuffer {
    /// `h_name`.
    _name: CString,
    /// The IPv4 addresses `h_addr_list` points at, in network byte order.
    _addrs: Vec<[u8; 4]>,
    /// `h_addr_list`, NULL-terminated.
    _list: Vec<*mut i8>,
    /// `h_aliases`: no aliases, just the terminating NULL.
    _aliases: Box<[*mut i8; 1]>,
    entry: HOSTENT,
}

thread_local! {
    /// The calling thread's last `gethostbyname` answer; the next one replaces it.
    static HOSTENT_BUFFER: RefCell<Option<Box<HostBuffer>>> = const { RefCell::new(None) };
}

/// Builds an `AF_INET` `HOSTENT` (`h_length` 4) for `name` with `addrs`, stores it in this
/// thread's [`HOSTENT_BUFFER`], and returns a pointer to it valid until the thread's next answer.
fn host_entry(name: &str, mut addrs: Vec<[u8; 4]>) -> *mut HOSTENT {
    let name = CString::new(name.replace('\0', "")).unwrap_or_default();
    let mut list: Vec<*mut i8> = addrs
        .iter_mut()
        .map(|a| a.as_mut_ptr().cast())
        .chain([ptr::null_mut()])
        .collect();
    let mut aliases = Box::new([ptr::null_mut()]);
    let entry = HOSTENT {
        h_name: name.as_ptr().cast_mut().cast(),
        h_aliases: aliases.as_mut_ptr(),
        h_addrtype: AF_INET as i16,
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
    HOSTENT_BUFFER.with_borrow_mut(|slot| *slot = Some(buffer));
    entry
}

/// Fails `gethostbyname` with Winsock error `code`: NULL, the code left for `WSAGetLastError`.
fn host_failure(code: i32) -> *mut HOSTENT {
    // SAFETY: sets the calling thread's Winsock error.
    unsafe { WSASetLastError(code) };
    ptr::null_mut()
}

/// Hook for `gethostbyname`. IPv4 only, as Winsock documents; a known name with no IPv4 address
/// fails with `WSANO_DATA`.
///
/// The non-name cases follow [Microsoft Learn: gethostbyname](https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-gethostbyname):
/// a NULL or empty name answers for the local computer's own host name, so it goes to Winsock as
/// the OS's answer; a legal IPv4 string is answered with that address and the string as `h_name`.
/// The page says an IPv6 string fails with `WSANO_DATA`, but the real call fails it with
/// `WSAHOST_NOT_FOUND` (measured on Windows 11 by tests/dns_win.rs
/// `gethostbyname_non_names_match_os`), which the sim follows. A string of only digits and dots
/// that is not a strict dotted quad (`127.1`, `1.2.3.256`) goes to Winsock, which alone decides
/// what it is; neither case is a name lookup.
unsafe extern "system" fn gethostbyname(name: *const u8) -> *mut HOSTENT {
    // SAFETY: the caller's name.
    let call = || unsafe { original::<GetHostByName>(&GETHOSTBYNAME)(name) };
    let answer = dispatch_resolver(|resolver| {
        if name.is_null() {
            return Answer::Done(call());
        }
        // SAFETY: the caller's NUL-terminated name.
        let text = unsafe { <Ansi as Text>::decode(name) };
        if text.is_empty() {
            return Answer::Done(call());
        }
        if let Ok(v4) = text.parse::<Ipv4Addr>() {
            return Answer::Done(host_entry(&text, vec![v4.octets()]));
        }
        let unscoped = text.split_once('%').map_or(text.as_str(), |(addr, _)| addr);
        if unscoped.parse::<std::net::Ipv6Addr>().is_ok() {
            return Answer::Done(host_failure(WSAHOST_NOT_FOUND));
        }
        if text.bytes().all(|b| b.is_ascii_digit() || b == b'.') {
            return Answer::Done(call());
        }
        Answer::Done(match resolver.lookup(&text) {
            Lookup::Real => return Answer::Real,
            Lookup::NotFound => host_failure(WSAHOST_NOT_FOUND),
            Lookup::TryAgain => host_failure(WSATRY_AGAIN),
            Lookup::Fail => host_failure(WSANO_RECOVERY),
            Lookup::Addrs { canonical, addrs } => {
                let v4: Vec<[u8; 4]> = addrs
                    .iter()
                    .filter_map(|ip| match ip {
                        IpAddr::V4(v4) => Some(v4.octets()),
                        IpAddr::V6(_) => None,
                    })
                    .collect();
                if v4.is_empty() {
                    host_failure(WSANO_DATA)
                } else {
                    host_entry(&canonical, v4)
                }
            }
        })
    });
    gai::settle(answer, "gethostbyname", call)
}
