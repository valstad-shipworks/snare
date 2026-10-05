//! The IP Helper (`iphlpapi.dll`) calls that enumerate interfaces, offered to the domain's
//! [`Net`](crate::Net) as an [`IpHlpCall`]. Signatures follow `netioapi.h` / `iphlpapi.h`; a
//! `NET_LUID_LH` travels as the `u64` it is (`ifdef.h`: a `ULONG64` union,
//! [Microsoft Learn: NET_LUID_LH](https://learn.microsoft.com/en-us/windows/win32/api/ifdef/ns-ifdef-net_luid_lh)).
//!
//! Every replacement follows one shape: check the pointers the sim needs, build the
//! [`IpHlpCall`], and [`offer`] it. `Some` is the sim's answer, returned as the export's own
//! return value; `None` (no domain on this thread, passthrough, or a backend that declines) falls
//! through to the original export saved in the matching `static`. A call with a null pointer the
//! sim would have to dereference also goes to the original, so the caller gets the real
//! function's own error for it rather than one the sim guessed. Two hooks differ:
//! `ConvertInterfaceAliasToLuid` answers a null `InterfaceLuid` itself, and `if_indextoname` does
//! not check its `name` buffer before offering the call.
//!
//! The hooks run on the caller's thread with no snare lock held; [`dispatch_net`] enters
//! passthrough before the backend runs, so whatever OS calls the backend makes go to the OS.

use std::ffi::{CStr, c_char, c_void};
use std::sync::atomic::AtomicUsize;

use crate::domain::dispatch_net;
use crate::hooks::{Hook, hook, original};
use crate::net::IpHlpCall;

/// The original `if_nametoindex` export, filled in when the hook is installed; 0 until then.
/// Every `static` below holds one export's original address the same way.
static IF_NAMETOINDEX: AtomicUsize = AtomicUsize::new(0);
/// The original `if_indextoname`.
static IF_INDEXTONAME: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceAliasToLuid`.
static ALIAS_TO_LUID: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceNameToLuidA`.
static NAME_TO_LUID_A: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceNameToLuidW`.
static NAME_TO_LUID_W: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceLuidToAlias`.
static LUID_TO_ALIAS: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceLuidToNameA`.
static LUID_TO_NAME_A: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceLuidToIndex`.
static LUID_TO_INDEX: AtomicUsize = AtomicUsize::new(0);
/// The original `ConvertInterfaceIndexToLuid`.
static INDEX_TO_LUID: AtomicUsize = AtomicUsize::new(0);
/// The original `GetIfEntry2`.
static GET_IF_ENTRY2: AtomicUsize = AtomicUsize::new(0);
/// The original `GetIfTable2`.
static GET_IF_TABLE2: AtomicUsize = AtomicUsize::new(0);
/// The original `GetUnicastIpAddressTable`.
static GET_UNICAST_TABLE: AtomicUsize = AtomicUsize::new(0);
/// The original `FreeMibTable`.
static FREE_MIB_TABLE: AtomicUsize = AtomicUsize::new(0);
/// The original `GetAdaptersAddresses`.
static GET_ADAPTERS_ADDRESSES: AtomicUsize = AtomicUsize::new(0);
/// The original `GetBestRoute2`.
static GET_BEST_ROUTE2: AtomicUsize = AtomicUsize::new(0);
/// The original `GetUdpStatistics`.
static GET_UDP_STATS: AtomicUsize = AtomicUsize::new(0);
/// The original `GetUdpStatisticsEx`.
static GET_UDP_STATS_EX: AtomicUsize = AtomicUsize::new(0);
/// The original `GetUdpStatisticsEx2`.
static GET_UDP_STATS_EX2: AtomicUsize = AtomicUsize::new(0);
/// The original `GetTcpStatistics`.
static GET_TCP_STATS: AtomicUsize = AtomicUsize::new(0);
/// The original `GetTcpStatisticsEx`.
static GET_TCP_STATS_EX: AtomicUsize = AtomicUsize::new(0);
/// The original `GetTcpStatisticsEx2`.
static GET_TCP_STATS_EX2: AtomicUsize = AtomicUsize::new(0);

/// The IP Helper hooks, each naming its `iphlpapi.dll` export, its replacement and the `static`
/// that receives the original.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!(
            "if_nametoindex",
            "iphlpapi.dll",
            if_nametoindex,
            IF_NAMETOINDEX
        ),
        hook!(
            "if_indextoname",
            "iphlpapi.dll",
            if_indextoname,
            IF_INDEXTONAME
        ),
        hook!(
            "ConvertInterfaceAliasToLuid",
            "iphlpapi.dll",
            alias_to_luid,
            ALIAS_TO_LUID
        ),
        hook!(
            "ConvertInterfaceNameToLuidA",
            "iphlpapi.dll",
            name_to_luid_a,
            NAME_TO_LUID_A
        ),
        hook!(
            "ConvertInterfaceNameToLuidW",
            "iphlpapi.dll",
            name_to_luid_w,
            NAME_TO_LUID_W
        ),
        hook!(
            "ConvertInterfaceLuidToAlias",
            "iphlpapi.dll",
            luid_to_alias,
            LUID_TO_ALIAS
        ),
        hook!(
            "ConvertInterfaceLuidToNameA",
            "iphlpapi.dll",
            luid_to_name_a,
            LUID_TO_NAME_A
        ),
        hook!(
            "ConvertInterfaceLuidToIndex",
            "iphlpapi.dll",
            luid_to_index,
            LUID_TO_INDEX
        ),
        hook!(
            "ConvertInterfaceIndexToLuid",
            "iphlpapi.dll",
            index_to_luid,
            INDEX_TO_LUID
        ),
        hook!("GetIfEntry2", "iphlpapi.dll", get_if_entry2, GET_IF_ENTRY2),
        hook!("GetIfTable2", "iphlpapi.dll", get_if_table2, GET_IF_TABLE2),
        hook!(
            "GetUnicastIpAddressTable",
            "iphlpapi.dll",
            get_unicast_table,
            GET_UNICAST_TABLE
        ),
        hook!(
            "FreeMibTable",
            "iphlpapi.dll",
            free_mib_table,
            FREE_MIB_TABLE
        ),
        hook!(
            "GetAdaptersAddresses",
            "iphlpapi.dll",
            get_adapters_addresses,
            GET_ADAPTERS_ADDRESSES
        ),
        hook!(
            "GetBestRoute2",
            "iphlpapi.dll",
            get_best_route2,
            GET_BEST_ROUTE2
        ),
        hook!(
            "GetUdpStatistics",
            "iphlpapi.dll",
            get_udp_stats,
            GET_UDP_STATS
        ),
        hook!(
            "GetUdpStatisticsEx",
            "iphlpapi.dll",
            get_udp_stats_ex,
            GET_UDP_STATS_EX
        ),
        hook!(
            "GetUdpStatisticsEx2",
            "iphlpapi.dll",
            get_udp_stats_ex2,
            GET_UDP_STATS_EX2
        ),
        hook!(
            "GetTcpStatistics",
            "iphlpapi.dll",
            get_tcp_stats,
            GET_TCP_STATS
        ),
        hook!(
            "GetTcpStatisticsEx",
            "iphlpapi.dll",
            get_tcp_stats_ex,
            GET_TCP_STATS_EX
        ),
        hook!(
            "GetTcpStatisticsEx2",
            "iphlpapi.dll",
            get_tcp_stats_ex2,
            GET_TCP_STATS_EX2
        ),
    ]
}

/// Offers `call` to the calling thread's domain. `Some` carries the export's return value (a
/// Win32 status, or the index / pointer `if_nametoindex` / `if_indextoname` return); `None`
/// means call the original.
fn offer(call: IpHlpCall<'_>) -> Option<i64> {
    // SAFETY: the pointers in `call` are the caller's, passed through unchanged.
    dispatch_net(|net| unsafe { net.iphlp(call) })
}

/// The NUL-terminated wide string at `p`, without its terminator.
///
/// # Safety
/// `p` is null or a NUL-terminated UTF-16 string.
unsafe fn wide<'a>(p: *const u16) -> Option<&'a [u16]> {
    if p.is_null() {
        return None;
    }
    let mut len = 0;
    // SAFETY: the caller's string is NUL-terminated.
    while unsafe { *p.add(len) } != 0 {
        len += 1;
    }
    // SAFETY: `len` units before the terminator are readable.
    Some(unsafe { std::slice::from_raw_parts(p, len) })
}

/// `ERROR_INVALID_PARAMETER` (`winerror.h`, 87), what `ConvertInterfaceAliasToLuid` returns for a
/// null `InterfaceLuid`
/// ([Microsoft Learn: System Error Codes (0-499)](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-);
/// [Microsoft Learn: ConvertInterfaceAliasToLuid](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacealiastoluid)).
const ERROR_INVALID_PARAMETER: u32 = 87;

/// `if_nametoindex`: the index of the interface with the NDIS name `name`, 0 when there is none
/// ([Microsoft Learn: if_nametoindex](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-if_nametoindex)).
/// A null `name` goes to the original.
unsafe extern "system" fn if_nametoindex(name: *const c_char) -> u32 {
    // SAFETY: `name` is the caller's C string or null.
    if !name.is_null()
        && let Some(r) = offer(IpHlpCall::NameToIndex(unsafe { CStr::from_ptr(name) }))
    {
        return r as u32;
    }
    // SAFETY: IF_NAMETOINDEX holds iphlpapi's if_nametoindex.
    unsafe { original::<unsafe extern "system" fn(*const c_char) -> u32>(&IF_NAMETOINDEX)(name) }
}

/// `if_indextoname`: writes the NDIS name of interface `index` into `name` (at least `IF_NAMESIZE`
/// bytes) and returns `name`, or null for an unknown index
/// ([Microsoft Learn: if_indextoname](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-if_indextoname)).
/// `name` is offered to the sim without a null check, and the sim writes through it for a known
/// index.
unsafe extern "system" fn if_indextoname(index: u32, name: *mut c_char) -> *mut c_char {
    if let Some(r) = offer(IpHlpCall::IndexToName { index, name }) {
        return r as *mut c_char;
    }
    // SAFETY: IF_INDEXTONAME holds iphlpapi's if_indextoname.
    unsafe {
        original::<unsafe extern "system" fn(u32, *mut c_char) -> *mut c_char>(&IF_INDEXTONAME)(
            index, name,
        )
    }
}

/// `ConvertInterfaceAliasToLuid`. A non-null alias with a null `luid` is answered here with
/// [`ERROR_INVALID_PARAMETER`], as the export documents; a null alias goes to the original
/// ([Microsoft Learn: ConvertInterfaceAliasToLuid](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacealiastoluid)).
unsafe extern "system" fn alias_to_luid(alias: *const u16, luid: *mut u64) -> u32 {
    // SAFETY: `alias` is the caller's wide string.
    if let Some(alias) = unsafe { wide(alias) } {
        if luid.is_null() {
            return ERROR_INVALID_PARAMETER;
        }
        if let Some(r) = offer(IpHlpCall::AliasToLuid { alias, luid }) {
            return r as u32;
        }
    }
    // SAFETY: ALIAS_TO_LUID holds iphlpapi's ConvertInterfaceAliasToLuid.
    unsafe {
        original::<unsafe extern "system" fn(*const u16, *mut u64) -> u32>(&ALIAS_TO_LUID)(
            alias, luid,
        )
    }
}

/// `ConvertInterfaceNameToLuidA`: the LUID an NDIS name such as `ethernet_32772` stands for
/// ([Microsoft Learn: ConvertInterfaceNameToLuidA](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacenametoluida)).
unsafe extern "system" fn name_to_luid_a(name: *const c_char, luid: *mut u64) -> u32 {
    if !name.is_null() && !luid.is_null() {
        // SAFETY: `name` is the caller's C string.
        let name = unsafe { CStr::from_ptr(name) };
        if let Some(r) = offer(IpHlpCall::NameToLuidA { name, luid }) {
            return r as u32;
        }
    }
    // SAFETY: NAME_TO_LUID_A holds iphlpapi's ConvertInterfaceNameToLuidA.
    unsafe {
        original::<unsafe extern "system" fn(*const c_char, *mut u64) -> u32>(&NAME_TO_LUID_A)(
            name, luid,
        )
    }
}

/// `ConvertInterfaceNameToLuidW`, the UTF-16 form of [`name_to_luid_a`]
/// ([Microsoft Learn: ConvertInterfaceNameToLuidW](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacenametoluidw)).
unsafe extern "system" fn name_to_luid_w(name: *const u16, luid: *mut u64) -> u32 {
    // SAFETY: `name` is the caller's wide string.
    if let Some(wname) = unsafe { wide(name) }
        && !luid.is_null()
        && let Some(r) = offer(IpHlpCall::NameToLuidW { name: wname, luid })
    {
        return r as u32;
    }
    // SAFETY: NAME_TO_LUID_W holds iphlpapi's ConvertInterfaceNameToLuidW.
    unsafe {
        original::<unsafe extern "system" fn(*const u16, *mut u64) -> u32>(&NAME_TO_LUID_W)(
            name, luid,
        )
    }
}

/// `ConvertInterfaceLuidToAlias`: the alias (friendly name) of an interface into `alias`, `len`
/// counted in UTF-16 units including the terminator
/// ([Microsoft Learn: ConvertInterfaceLuidToAlias](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoalias)).
unsafe extern "system" fn luid_to_alias(luid: *const u64, alias: *mut u16, len: usize) -> u32 {
    if !luid.is_null() && !alias.is_null() {
        // SAFETY: `luid` points to the caller's NET_LUID.
        let value = unsafe { luid.read_unaligned() };
        if let Some(r) = offer(IpHlpCall::LuidToAlias {
            luid: value,
            alias,
            len,
        }) {
            return r as u32;
        }
    }
    // SAFETY: LUID_TO_ALIAS holds iphlpapi's ConvertInterfaceLuidToAlias.
    unsafe {
        original::<unsafe extern "system" fn(*const u64, *mut u16, usize) -> u32>(&LUID_TO_ALIAS)(
            luid, alias, len,
        )
    }
}

/// `ConvertInterfaceLuidToNameA`: the NDIS name of an interface into `name`, `len` counted in
/// bytes including the terminator
/// ([Microsoft Learn: ConvertInterfaceLuidToNameA](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtonamea)).
unsafe extern "system" fn luid_to_name_a(luid: *const u64, name: *mut c_char, len: usize) -> u32 {
    if !luid.is_null() && !name.is_null() {
        // SAFETY: `luid` points to the caller's NET_LUID.
        let value = unsafe { luid.read_unaligned() };
        if let Some(r) = offer(IpHlpCall::LuidToNameA {
            luid: value,
            name,
            len,
        }) {
            return r as u32;
        }
    }
    // SAFETY: LUID_TO_NAME_A holds iphlpapi's ConvertInterfaceLuidToNameA.
    unsafe {
        original::<unsafe extern "system" fn(*const u64, *mut c_char, usize) -> u32>(
            &LUID_TO_NAME_A,
        )(luid, name, len)
    }
}

/// `ConvertInterfaceLuidToIndex`
/// ([Microsoft Learn: ConvertInterfaceLuidToIndex](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex)).
unsafe extern "system" fn luid_to_index(luid: *const u64, index: *mut u32) -> u32 {
    if !luid.is_null() && !index.is_null() {
        // SAFETY: `luid` points to the caller's NET_LUID.
        let value = unsafe { luid.read_unaligned() };
        if let Some(r) = offer(IpHlpCall::LuidToIndex { luid: value, index }) {
            return r as u32;
        }
    }
    // SAFETY: LUID_TO_INDEX holds iphlpapi's ConvertInterfaceLuidToIndex.
    unsafe {
        original::<unsafe extern "system" fn(*const u64, *mut u32) -> u32>(&LUID_TO_INDEX)(
            luid, index,
        )
    }
}

/// `ConvertInterfaceIndexToLuid`
/// ([Microsoft Learn: ConvertInterfaceIndexToLuid](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceindextoluid)).
unsafe extern "system" fn index_to_luid(index: u32, luid: *mut u64) -> u32 {
    if !luid.is_null()
        && let Some(r) = offer(IpHlpCall::IndexToLuid { index, luid })
    {
        return r as u32;
    }
    // SAFETY: INDEX_TO_LUID holds iphlpapi's ConvertInterfaceIndexToLuid.
    unsafe {
        original::<unsafe extern "system" fn(u32, *mut u64) -> u32>(&INDEX_TO_LUID)(index, luid)
    }
}

/// `GetIfEntry2`: fills the caller's `MIB_IF_ROW2`, chosen by its `InterfaceLuid` or, when that
/// is zero, its `InterfaceIndex`
/// ([Microsoft Learn: GetIfEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2)).
unsafe extern "system" fn get_if_entry2(row: *mut u8) -> u32 {
    if !row.is_null()
        && let Some(r) = offer(IpHlpCall::GetIfEntry2(row))
    {
        return r as u32;
    }
    // SAFETY: GET_IF_ENTRY2 holds iphlpapi's GetIfEntry2.
    unsafe { original::<unsafe extern "system" fn(*mut u8) -> u32>(&GET_IF_ENTRY2)(row) }
}

/// `GetIfTable2`: a `MIB_IF_TABLE2` the sim allocates, which the caller frees with
/// `FreeMibTable` ([`free_mib_table`])
/// ([Microsoft Learn: GetIfTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2)).
unsafe extern "system" fn get_if_table2(table: *mut *mut u8) -> u32 {
    if !table.is_null()
        && let Some(r) = offer(IpHlpCall::GetIfTable2(table))
    {
        return r as u32;
    }
    // SAFETY: GET_IF_TABLE2 holds iphlpapi's GetIfTable2.
    unsafe { original::<unsafe extern "system" fn(*mut *mut u8) -> u32>(&GET_IF_TABLE2)(table) }
}

/// `GetUnicastIpAddressTable` for `family` (`AF_UNSPEC`, `AF_INET` or `AF_INET6`), allocated like
/// [`get_if_table2`]'s table
/// ([Microsoft Learn: GetUnicastIpAddressTable](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getunicastipaddresstable)).
unsafe extern "system" fn get_unicast_table(family: u16, table: *mut *mut u8) -> u32 {
    if !table.is_null()
        && let Some(r) = offer(IpHlpCall::GetUnicastIpAddressTable { family, table })
    {
        return r as u32;
    }
    // SAFETY: GET_UNICAST_TABLE holds iphlpapi's GetUnicastIpAddressTable.
    unsafe {
        original::<unsafe extern "system" fn(u16, *mut *mut u8) -> u32>(&GET_UNICAST_TABLE)(
            family, table,
        )
    }
}

/// `FreeMibTable`. The sim frees a table it allocated (its backend answers `Some`); any other
/// pointer is iphlpapi's own and goes to the original
/// ([Microsoft Learn: FreeMibTable](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freemibtable)).
unsafe extern "system" fn free_mib_table(memory: *mut c_void) {
    if !memory.is_null() && offer(IpHlpCall::FreeMibTable(memory.cast())).is_some() {
        return;
    }
    // SAFETY: FREE_MIB_TABLE holds iphlpapi's FreeMibTable.
    unsafe { original::<unsafe extern "system" fn(*mut c_void)>(&FREE_MIB_TABLE)(memory) }
}

/// `GetAdaptersAddresses`, with its size protocol: a null or short buffer gets
/// `ERROR_BUFFER_OVERFLOW` and the needed size in `*size`. `reserved` is unused by the sim
/// ([Microsoft Learn: GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)).
unsafe extern "system" fn get_adapters_addresses(
    family: u32,
    flags: u32,
    reserved: *mut c_void,
    addresses: *mut u8,
    size: *mut u32,
) -> u32 {
    if !size.is_null()
        && let Some(r) = offer(IpHlpCall::GetAdaptersAddresses {
            family,
            flags,
            addresses,
            size,
        })
    {
        return r as u32;
    }
    // SAFETY: GET_ADAPTERS_ADDRESSES holds iphlpapi's GetAdaptersAddresses.
    unsafe {
        original::<unsafe extern "system" fn(u32, u32, *mut c_void, *mut u8, *mut u32) -> u32>(
            &GET_ADAPTERS_ADDRESSES,
        )(family, flags, reserved, addresses, size)
    }
}

/// `GetBestRoute2`: the best route to `destination` and the source address it would use. The
/// interface is pinned by `luid` when it is non-null and nonzero, else by `index` when nonzero;
/// `options` is unused, as on Windows
/// ([Microsoft Learn: GetBestRoute2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2)).
unsafe extern "system" fn get_best_route2(
    luid: *const u64,
    index: u32,
    source: *const u8,
    destination: *const u8,
    options: u32,
    route: *mut u8,
    best_source: *mut u8,
) -> u32 {
    if !destination.is_null()
        && !route.is_null()
        && !best_source.is_null()
        && let Some(r) = offer(IpHlpCall::GetBestRoute2 {
            luid,
            index,
            source,
            destination,
            options,
            route,
            best_source,
        })
    {
        return r as u32;
    }
    // SAFETY: GET_BEST_ROUTE2 holds iphlpapi's GetBestRoute2.
    unsafe {
        original::<
            unsafe extern "system" fn(
                *const u64,
                u32,
                *const u8,
                *const u8,
                u32,
                *mut u8,
                *mut u8,
            ) -> u32,
        >(&GET_BEST_ROUTE2)(
            luid,
            index,
            source,
            destination,
            options,
            route,
            best_source,
        )
    }
}

/// `AF_INET` (`ws2def.h`), the family the non-`Ex` statistics calls report.
const AF_INET: u32 = 2;

/// The signature `GetUdpStatistics`/`GetTcpStatistics` share.
type StatsFn = unsafe extern "system" fn(*mut u8) -> u32;
/// The signature of their `Ex` and `Ex2` forms.
type StatsExFn = unsafe extern "system" fn(*mut u8, u32) -> u32;

/// Offers a statistics call to the sim, else calls `original`. A null `stats` goes to the
/// original, which fails it with `ERROR_INVALID_PARAMETER`.
fn stats_call(stats: *mut u8, call: IpHlpCall<'static>, original: impl FnOnce() -> u32) -> u32 {
    if !stats.is_null()
        && let Some(r) = offer(call)
    {
        return r as u32;
    }
    original()
}

/// `GetUdpStatistics`: the IPv4 UDP counters
/// ([Microsoft Learn: GetUdpStatistics](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudpstatistics)).
unsafe extern "system" fn get_udp_stats(stats: *mut u8) -> u32 {
    let call = IpHlpCall::UdpStatistics {
        family: AF_INET,
        stats,
        wide: false,
    };
    // SAFETY: GET_UDP_STATS holds iphlpapi's GetUdpStatistics.
    stats_call(stats, call, || unsafe {
        original::<StatsFn>(&GET_UDP_STATS)(stats)
    })
}

/// `GetUdpStatisticsEx`
/// ([Microsoft Learn: GetUdpStatisticsEx](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudpstatisticsex)).
unsafe extern "system" fn get_udp_stats_ex(stats: *mut u8, family: u32) -> u32 {
    let call = IpHlpCall::UdpStatistics {
        family,
        stats,
        wide: false,
    };
    // SAFETY: GET_UDP_STATS_EX holds iphlpapi's GetUdpStatisticsEx.
    stats_call(stats, call, || unsafe {
        original::<StatsExFn>(&GET_UDP_STATS_EX)(stats, family)
    })
}

/// `GetUdpStatisticsEx2`, with 64-bit datagram counts
/// ([Microsoft Learn: GetUdpStatisticsEx2](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudpstatisticsex2)).
unsafe extern "system" fn get_udp_stats_ex2(stats: *mut u8, family: u32) -> u32 {
    let call = IpHlpCall::UdpStatistics {
        family,
        stats,
        wide: true,
    };
    // SAFETY: GET_UDP_STATS_EX2 holds iphlpapi's GetUdpStatisticsEx2.
    stats_call(stats, call, || unsafe {
        original::<StatsExFn>(&GET_UDP_STATS_EX2)(stats, family)
    })
}

/// `GetTcpStatistics`: the IPv4 TCP counters
/// ([Microsoft Learn: GetTcpStatistics](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcpstatistics)).
unsafe extern "system" fn get_tcp_stats(stats: *mut u8) -> u32 {
    let call = IpHlpCall::TcpStatistics {
        family: AF_INET,
        stats,
        wide: false,
    };
    // SAFETY: GET_TCP_STATS holds iphlpapi's GetTcpStatistics.
    stats_call(stats, call, || unsafe {
        original::<StatsFn>(&GET_TCP_STATS)(stats)
    })
}

/// `GetTcpStatisticsEx`
/// ([Microsoft Learn: GetTcpStatisticsEx](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcpstatisticsex)).
unsafe extern "system" fn get_tcp_stats_ex(stats: *mut u8, family: u32) -> u32 {
    let call = IpHlpCall::TcpStatistics {
        family,
        stats,
        wide: false,
    };
    // SAFETY: GET_TCP_STATS_EX holds iphlpapi's GetTcpStatisticsEx.
    stats_call(stats, call, || unsafe {
        original::<StatsExFn>(&GET_TCP_STATS_EX)(stats, family)
    })
}

/// `GetTcpStatisticsEx2`, with 64-bit segment counts
/// ([Microsoft Learn: GetTcpStatisticsEx2](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-gettcpstatisticsex2)).
unsafe extern "system" fn get_tcp_stats_ex2(stats: *mut u8, family: u32) -> u32 {
    let call = IpHlpCall::TcpStatistics {
        family,
        stats,
        wide: true,
    };
    // SAFETY: GET_TCP_STATS_EX2 holds iphlpapi's GetTcpStatisticsEx2.
    stats_call(stats, call, || unsafe {
        original::<StatsExFn>(&GET_TCP_STATS_EX2)(stats, family)
    })
}
