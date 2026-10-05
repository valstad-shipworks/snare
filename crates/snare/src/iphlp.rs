//! The IP Helper view of the sim's topology: interface LUIDs, names and aliases, `MIB_IF_ROW2`,
//! the unicast address table, `GetAdaptersAddresses` and `GetBestRoute2`, rendered through the
//! `windows-sys` types so every layout is the SDK's.
//!
//! Every answer is computed afresh from a [`SimShared::nics`] snapshot taken at the top of
//! [`call`], sorted by interface index; nothing here caches topology. An interface has three
//! names, as on Windows: its alias (the friendly name, the sim's `NicSpec::name`, e.g. `eth0`),
//! its NDIS name (`ethernet_32772`, derived from the LUID and parsed back without a lookup), and
//! its adapter GUID string. The only state of the module's own is [`TABLES`], the record of the
//! MIB tables it handed out, so that `FreeMibTable` can tell them from iphlpapi's.
//!
//! The Win32 status codes returned for a missing interface by alias, name and index lookups, the
//! LUID-to-index and LUID-to-alias conversions and `GetIfEntry2` by index were measured against
//! the real iphlpapi: `nic_iphlpapi_win`'s `not_found_codes_pinned` test runs the same probes on
//! the host and in the sim and requires equal results. The other codes follow Microsoft Learn or
//! are marked as snare's choice where they are made.

use std::alloc::Layout;
use std::collections::HashMap;
use std::ffi::c_char;
use std::mem::{offset_of, size_of, zeroed};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use snare_interpose::{IpHlpCall, NetResult};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    IF_TYPE_ETHERNET_CSMACD, IF_TYPE_SOFTWARE_LOOPBACK, IP_ADAPTER_ADDRESSES_LH,
    IP_ADAPTER_UNICAST_ADDRESS_LH, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_IPFORWARD_ROW2,
    MIB_UNICASTIPADDRESS_ROW, MIB_UNICASTIPADDRESS_TABLE,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusDown, IfOperStatusUp, MediaConnectStateConnected, MediaConnectStateDisconnected,
    NET_IF_ACCESS_BROADCAST, NET_IF_ADMIN_STATUS_DOWN, NET_IF_ADMIN_STATUS_UP,
    NET_IF_CONNECTION_DEDICATED, NdisMedium802_3, NdisMediumLoopback,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, IpDadStatePreferred, IpPrefixOriginManual, IpSuffixOriginManual,
    MIB_IPPROTO_LOCAL, MIB_IPPROTO_NETMGMT, NlroManual, SOCKADDR, SOCKADDR_IN, SOCKADDR_IN6,
    SOCKADDR_INET,
};
use windows_sys::core::GUID;

use crate::netif::NicSnapshot;
use crate::scope::SimShared;

/// Success. This and the status codes below are `winerror.h`'s
/// ([Microsoft Learn: System Error Codes (0-499)](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-);
/// `ERROR_NETWORK_UNREACHABLE` in
/// [Microsoft Learn: System Error Codes (1000-1299)](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--1000-1299-)).
const ERROR_SUCCESS: u32 = 0;
/// No such interface (LUID or index).
const ERROR_FILE_NOT_FOUND: u32 = 2;
/// The caller's name buffer is too short.
const ERROR_NOT_ENOUGH_MEMORY: u32 = 8;
/// A bad family, destination or alias.
const ERROR_INVALID_PARAMETER: u32 = 87;
/// `GetAdaptersAddresses` needs a bigger buffer.
const ERROR_BUFFER_OVERFLOW: u32 = 111;
/// Not a valid NDIS interface name.
const ERROR_INVALID_NAME: u32 = 123;
/// No route to the destination.
const ERROR_NETWORK_UNREACHABLE: u32 = 1231;

/// `GAA_FLAG_SKIP_UNICAST` (`iptypes.h`).
///
/// "Do not return unicast addresses"
/// ([Microsoft Learn: GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses)).
const GAA_FLAG_SKIP_UNICAST: u32 = 0x1;

/// The `NetLuidIndex` Windows numbers its non-loopback interfaces from.
///
/// Observed on Windows hosts, whose Ethernet adapters carry NDIS names `ethernet_32768`,
/// `ethernet_32769`, …; Microsoft does not document the numbering. The sim adds its own interface
/// index so the name stays unique and reversible. Not pinned against the host by a test
/// (`nic_iphlpapi_win`'s `if_nametoindex_and_best_route` checks only the sim's own round trip).
const LUID_INDEX_BASE: u32 = 32768;

/// A `NET_LUID`'s value: `Reserved:24, NetLuidIndex:24, IfType:16` (`ifdef.h`).
///
/// Loopback is `IF_TYPE_SOFTWARE_LOOPBACK` (24) with index 0 (`loopback_0`, the name Windows hosts
/// show; observed, not documented); any other interface is `IF_TYPE_ETHERNET_CSMACD` (6) at [`LUID_INDEX_BASE`] plus its interface
/// index. `Reserved` stays 0
/// ([Microsoft Learn: NET_LUID_LH](https://learn.microsoft.com/en-us/windows/win32/api/ifdef/ns-ifdef-net_luid_lh)).
fn luid(nic: &NicSnapshot) -> u64 {
    let (if_type, index) = if nic.loopback {
        (IF_TYPE_SOFTWARE_LOOPBACK, 0)
    } else {
        (IF_TYPE_ETHERNET_CSMACD, LUID_INDEX_BASE + nic.index)
    };
    ((if_type as u64) << 48) | ((index as u64 & 0xff_ffff) << 24)
}

/// The prefix of an NDIS interface name for an `IfType` (`ethernet_…`, `loopback_…`, the forms
/// `ConvertInterfaceLuidToNameA` returns on Windows hosts; observed, the page does not give the
/// format); `None` for a type the sim never models.
fn type_name(if_type: u32) -> Option<&'static str> {
    match if_type {
        IF_TYPE_ETHERNET_CSMACD => Some("ethernet"),
        IF_TYPE_SOFTWARE_LOOPBACK => Some("loopback"),
        _ => None,
    }
}

/// The NDIS interface name of a LUID (`ConvertInterfaceLuidToNameA`), such as `ethernet_32772`.
fn luid_name(luid: u64) -> Option<String> {
    let if_type = (luid >> 48) as u32;
    let index = (luid >> 24) & 0xff_ffff;
    Some(format!("{}_{index}", type_name(if_type)?))
}

/// The LUID an NDIS interface name stands for, parsed rather than looked up.
///
/// The name must be `<type>_<index>` with a known type prefix and an index that fits the 24-bit
/// `NetLuidIndex`. The LUID need not belong to an existing interface; callers look it up.
fn parse_luid_name(name: &str) -> Option<u64> {
    let (prefix, index) = name.rsplit_once('_')?;
    let index: u64 = index.parse().ok().filter(|i| *i <= 0xff_ffff)?;
    let if_type = [IF_TYPE_ETHERNET_CSMACD, IF_TYPE_SOFTWARE_LOOPBACK]
        .into_iter()
        .find(|t| type_name(*t) == Some(prefix))?;
    Some(((if_type as u64) << 48) | (index << 24))
}

/// The interface's adapter GUID, a snare choice: `Data1`/`Data2` spell `"snare"` in ASCII
/// (`0x736e6172`, `0x6500`), `Data3` is 1 for loopback, and the last four bytes of `Data4` are the
/// interface index big-endian. Stable across runs and distinct per interface.
pub(crate) fn guid(nic: &NicSnapshot) -> GUID {
    let i = nic.index.to_be_bytes();
    GUID {
        data1: 0x736e_6172,
        data2: 0x6500,
        data3: nic.loopback as u16,
        data4: [0, 0, 0, 0, i[0], i[1], i[2], i[3]],
    }
}

/// `g` in the braced, upper-case registry form (`{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`) that
/// `IP_ADAPTER_ADDRESSES::AdapterName` carries on Windows hosts. Observed: the
/// IP_ADAPTER_ADDRESSES_LH page only calls it the adapter's permanent name.
pub(crate) fn guid_string(g: &GUID) -> String {
    let d = g.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// The adapter description (`MIB_IF_ROW2::Description`, `IP_ADAPTER_ADDRESSES::Description`):
/// the text Windows hosts show for their loopback adapter (observed, not documented), a
/// snare-made one for the rest.
pub(crate) fn description(nic: &NicSnapshot) -> String {
    if nic.loopback {
        "Software Loopback Interface 1".to_string()
    } else {
        format!("snare virtual Ethernet adapter #{}", nic.index)
    }
}

/// `s` as NUL-terminated UTF-16.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copies `s` into a fixed `WCHAR` array (`MIB_IF_ROW2::Alias` and `Description` are
/// `IF_MAX_STRING_SIZE + 1` = 257 units), truncating to fit and always leaving it
/// NUL-terminated.
fn copy_wide(dst: &mut [u16], s: &str) {
    let w = wide(s);
    let n = w.len().min(dst.len());
    dst[..n].copy_from_slice(&w[..n]);
    if n == dst.len()
        && let Some(last) = dst.last_mut()
    {
        *last = 0;
    }
}

/// `IfOperStatusUp` while the interface is running (administratively up with carrier), else
/// `IfOperStatusDown`.
fn oper_status(nic: &NicSnapshot) -> i32 {
    if nic.running() {
        IfOperStatusUp
    } else {
        IfOperStatusDown
    }
}

/// The interface's link speed in bits per second.
///
/// An interface with no configured speed (loopback among them) reports 1 073 741 824 (2^30)
/// bit/s, the "1 Gb/s" Windows shows for `Software Loopback Interface 1`. That value was observed
/// on Windows hosts; it is not documented and no test pins it.
fn speed(nic: &NicSnapshot) -> u64 {
    nic.spec
        .speed_mbps
        .map_or(1_073_741_824, |m| m as u64 * 1_000_000)
}

/// Fills a `MIB_IF_ROW2` for `nic`, zeroing it first
/// ([Microsoft Learn: MIB_IF_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2)).
/// Loopback has no physical address and NDIS medium `NdisMediumLoopback`; the rest are 802.3
/// Ethernet. Counters come from the sim's interface counters: `InUcastPkts` is received packets
/// less multicast, and `InUnknownProtos` the frames no protocol took (`rx_nohandler`).
fn fill_row(row: &mut MIB_IF_ROW2, nic: &NicSnapshot) {
    *row = unsafe { zeroed() };
    row.InterfaceLuid.Value = luid(nic);
    row.InterfaceIndex = nic.index;
    row.InterfaceGuid = guid(nic);
    copy_wide(&mut row.Alias, &nic.spec.name);
    copy_wide(&mut row.Description, &description(nic));
    if !nic.loopback {
        row.PhysicalAddressLength = 6;
        row.PhysicalAddress[..6].copy_from_slice(&nic.hw_addr());
        row.PermanentPhysicalAddress[..6].copy_from_slice(&nic.hw_addr());
    }
    row.Mtu = nic.spec.mtu;
    row.PhysicalMediumType = nic.physical_medium();
    if nic.loopback {
        row.Type = IF_TYPE_SOFTWARE_LOOPBACK;
        row.MediaType = NdisMediumLoopback;
    } else {
        row.Type = IF_TYPE_ETHERNET_CSMACD;
        row.MediaType = NdisMedium802_3;
    }
    row.AccessType = NET_IF_ACCESS_BROADCAST;
    row.OperStatus = oper_status(nic);
    row.AdminStatus = if nic.spec.admin_up {
        NET_IF_ADMIN_STATUS_UP
    } else {
        NET_IF_ADMIN_STATUS_DOWN
    };
    row.MediaConnectState = if nic.spec.carrier {
        MediaConnectStateConnected
    } else {
        MediaConnectStateDisconnected
    };
    row.ConnectionType = NET_IF_CONNECTION_DEDICATED;
    row.TransmitLinkSpeed = speed(nic);
    row.ReceiveLinkSpeed = speed(nic);
    let c = &nic.counters;
    row.InOctets = c.rx_bytes;
    row.InUcastPkts = c.rx_packets.saturating_sub(c.multicast);
    row.InNUcastPkts = c.multicast;
    row.InDiscards = c.rx_dropped;
    row.InErrors = c.rx_errors;
    row.InUnknownProtos = c.rx_nohandler;
    row.OutOctets = c.tx_bytes;
    row.OutUcastPkts = c.tx_packets;
    row.OutDiscards = c.tx_dropped;
    row.OutErrors = c.tx_errors;
}

/// `ip` as a `SOCKADDR_INET` with port 0. A link-local IPv6 address (`fe80::/10`, RFC 4291
/// §2.5.6) carries `scope`, the interface index, as its `sin6_scope_id`, which is how Windows
/// numbers link-local zones (RFC 4007 §6); every other address leaves it 0.
fn sockaddr_inet(ip: IpAddr, scope: u32) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
            if v6.segments()[0] & 0xffc0 == 0xfe80 {
                sa.Ipv6.Anonymous.sin6_scope_id = scope;
            }
        }
    }
    sa
}

/// The address in the caller's `SOCKADDR_INET` at `sa`, or `None` for a family other than
/// `AF_INET`/`AF_INET6`. `sa` must point to a readable `SOCKADDR_INET`.
fn read_inet(sa: *const u8) -> Option<IpAddr> {
    let sa = unsafe { &*sa.cast::<SOCKADDR_INET>() };
    match unsafe { sa.si_family } {
        AF_INET => Some(IpAddr::V4(Ipv4Addr::from(
            unsafe { sa.Ipv4.sin_addr.S_un.S_addr }.to_ne_bytes(),
        ))),
        AF_INET6 => Some(IpAddr::V6(Ipv6Addr::from(unsafe {
            sa.Ipv6.sin6_addr.u.Byte
        }))),
        _ => None,
    }
}

/// Whether `ip` belongs in a listing for address `family`; `AF_UNSPEC` (0) admits both.
fn family_matches(family: u32, ip: IpAddr) -> bool {
    match family as u16 {
        AF_INET => ip.is_ipv4(),
        AF_INET6 => ip.is_ipv6(),
        _ => true,
    }
}

/// The addresses Windows binds to an interface: none while it lacks carrier (media sense).
///
/// The sim lists no address on an interface that is not running (down, or without carrier), so
/// code that waits for its address to appear sees the link come up. This is snare's model of
/// Windows media sense, not a measured property of current Windows.
fn live_addresses(nic: &NicSnapshot) -> impl Iterator<Item = &crate::netif::IpNet> {
    nic.spec.addresses.iter().filter(move |_| nic.running())
}

/// Every MIB table [`alloc_table`] handed out and not yet freed, keyed by address, with the
/// layout `dealloc` needs. Process-wide because a table may be freed on any thread, even after
/// its sim ended. Held only for one insert or remove, never across a call out; a poisoned lock is
/// taken over, since the map stays consistent whatever panicked.
static TABLES: Mutex<Option<HashMap<usize, Layout>>> = Mutex::new(None);

/// A zeroed allocation `FreeMibTable` recognises as the sim's.
///
/// 8-byte aligned (the rows hold `u64`s) and at least 8 bytes long. Panics if the allocator fails,
/// rather than handing the caller a null table with `ERROR_SUCCESS`.
fn alloc_table(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size.max(8), 8).expect("table layout");
    let p = unsafe { std::alloc::alloc_zeroed(layout) };
    assert!(!p.is_null(), "MIB table allocation");
    TABLES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert_with(HashMap::new)
        .insert(p as usize, layout);
    p
}

/// Frees `p` if [`alloc_table`] made it; `false` for any other pointer, which the hook then
/// passes to the real `FreeMibTable`.
fn free_table(p: *mut u8) -> bool {
    let layout = TABLES
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_mut()
        .and_then(|t| t.remove(&(p as usize)));
    match layout {
        Some(layout) => {
            unsafe { std::alloc::dealloc(p, layout) };
            true
        }
        None => false,
    }
}

/// The call handled, returning Win32 status `code`.
fn done(code: u32) -> Option<NetResult> {
    Some(NetResult::Ok(code as i64))
}

/// Fills the UDP (`udp_call`) or TCP statistics struct of `family`, the 64-bit form when
/// `wide`, from the sim's counters ([`crate::netstats::windows`]). Any family but `AF_INET` and
/// `AF_INET6` goes to the real call, which answers `ERROR_NOT_SUPPORTED` (50) for it, as measured
/// on Windows 11.
///
/// # Safety
/// `stats` is writable for the struct `udp_call` and `wide` name.
unsafe fn statistics(
    shared: &SimShared,
    udp_call: bool,
    family: u32,
    stats: *mut u8,
    wide: bool,
) -> Option<NetResult> {
    use crate::netstats::windows as w;
    let v6 = match u16::try_from(family) {
        Ok(AF_INET) => false,
        Ok(AF_INET6) => true,
        _ => return None,
    };
    let c = shared.proto_counters();
    let (udp, tcp) = if v6 {
        (c.udp6, c.tcp6)
    } else {
        (c.udp4, c.tcp4)
    };
    unsafe fn put<T>(p: *mut u8, v: T) {
        unsafe { p.cast::<T>().write_unaligned(v) }
    }
    unsafe {
        match (udp_call, wide) {
            (true, false) => put(stats, w::udp(&udp)),
            (true, true) => put(stats, w::udp2(&udp)),
            (false, false) => put(stats, w::tcp(&tcp)),
            (false, true) => put(stats, w::tcp2(&tcp)),
        }
    }
    done(0)
}

/// Answers one IP Helper call from `shared`'s topology.
///
/// # Safety
/// The pointers in `call` are the caller's, valid as the matching function documents.
pub(crate) unsafe fn call(shared: &SimShared, call: IpHlpCall<'_>) -> Option<NetResult> {
    // One snapshot serves the whole call, so a table and the rows it counts always agree.
    let mut nics = shared.nics();
    nics.sort_by_key(|n| n.index);
    let by_luid = |l: u64| nics.iter().find(|n| luid(n) == l);
    let by_index = |i: u32| nics.iter().find(|n| n.index == i);
    match call {
        // if_nametoindex: 0 for an unknown name (Microsoft Learn: if_nametoindex).
        IpHlpCall::NameToIndex(name) => {
            let found = name
                .to_str()
                .ok()
                .and_then(parse_luid_name)
                .and_then(by_luid);
            Some(NetResult::Ok(found.map_or(0, |n| n.index as i64)))
        }
        // if_indextoname: returns `name`, or null for an unknown index. The caller's buffer is
        // at least IF_NAMESIZE bytes, far longer than any name the sim makes.
        IpHlpCall::IndexToName { index, name } => {
            let Some(nic) = by_index(index) else {
                return Some(NetResult::Ok(0));
            };
            if name.is_null() {
                return Some(NetResult::Ok(0));
            }
            let text = luid_name(luid(nic)).unwrap_or_default();
            // The caller's buffer holds IF_NAMESIZE (NDIS_IF_MAX_STRING_SIZE + 1 = 257) bytes
            // (netioapi.h; Microsoft Learn: if_indextoname).
            let len = text.len().min(256);
            unsafe {
                std::ptr::copy_nonoverlapping(text.as_ptr(), name.cast::<u8>(), len);
                *name.add(len) = 0;
            }
            Some(NetResult::Ok(name as i64))
        }
        // Aliases compare exactly with the sim's interface names.
        IpHlpCall::AliasToLuid { alias, luid: out } => {
            let alias = String::from_utf16_lossy(alias);
            match nics.iter().find(|n| n.spec.name == alias) {
                Some(nic) => {
                    unsafe { out.write_unaligned(luid(nic)) };
                    done(ERROR_SUCCESS)
                }
                // Pinned against the real call by nic_iphlpapi_win's not_found_codes_pinned.
                None => done(ERROR_INVALID_PARAMETER),
            }
        }
        IpHlpCall::NameToLuidA { name, luid: out } => unsafe {
            name_to_luid(name.to_str().ok(), out)
        },
        IpHlpCall::NameToLuidW { name, luid: out } => {
            let name = String::from_utf16(name).ok();
            unsafe { name_to_luid(name.as_deref(), out) }
        }
        // `len` counts UTF-16 units including the terminator; too short is
        // ERROR_NOT_ENOUGH_MEMORY (Microsoft Learn: ConvertInterfaceLuidToAlias). An unknown
        // LUID is ERROR_FILE_NOT_FOUND, as not_found_codes_pinned measured, where the page says
        // ERROR_INVALID_PARAMETER.
        IpHlpCall::LuidToAlias {
            luid: l,
            alias,
            len,
        } => {
            let Some(nic) = by_luid(l) else {
                return done(ERROR_FILE_NOT_FOUND);
            };
            let w = wide(&nic.spec.name);
            if w.len() > len {
                return done(ERROR_NOT_ENOUGH_MEMORY);
            }
            unsafe { std::ptr::copy_nonoverlapping(w.as_ptr(), alias, w.len()) };
            done(ERROR_SUCCESS)
        }
        // Names any well-formed LUID, existing or not; only an unknown IfType is
        // ERROR_INVALID_PARAMETER. That is snare's choice, not measured: the page lists
        // ERROR_INVALID_PARAMETER for an invalid LUID, and not_found_codes_pinned does not probe
        // this call. `len` counts bytes including the terminator
        // (Microsoft Learn: ConvertInterfaceLuidToNameA).
        IpHlpCall::LuidToNameA { luid: l, name, len } => {
            let Some(text) = luid_name(l) else {
                return done(ERROR_INVALID_PARAMETER);
            };
            if text.len() + 1 > len {
                return done(ERROR_NOT_ENOUGH_MEMORY);
            }
            unsafe {
                std::ptr::copy_nonoverlapping(text.as_ptr(), name.cast::<u8>(), text.len());
                *name.add(text.len()) = 0 as c_char;
            }
            done(ERROR_SUCCESS)
        }
        IpHlpCall::LuidToIndex { luid: l, index } => match by_luid(l) {
            Some(nic) => {
                unsafe { index.write_unaligned(nic.index) };
                done(ERROR_SUCCESS)
            }
            None => done(ERROR_FILE_NOT_FOUND),
        },
        IpHlpCall::IndexToLuid { index, luid: out } => match by_index(index) {
            Some(nic) => {
                unsafe { out.write_unaligned(luid(nic)) };
                done(ERROR_SUCCESS)
            }
            None => done(ERROR_FILE_NOT_FOUND),
        },
        // InterfaceLuid selects the row when nonzero, else InterfaceIndex
        // (Microsoft Learn: GetIfEntry2). With both zero the page documents
        // ERROR_INVALID_PARAMETER; the sim looks up index 0 and returns ERROR_FILE_NOT_FOUND.
        IpHlpCall::GetIfEntry2(row) => {
            let row = unsafe { &mut *row.cast::<MIB_IF_ROW2>() };
            let wanted = unsafe { row.InterfaceLuid.Value };
            let nic = if wanted != 0 {
                by_luid(wanted)
            } else {
                by_index(row.InterfaceIndex)
            };
            match nic {
                Some(nic) => {
                    fill_row(row, nic);
                    done(ERROR_SUCCESS)
                }
                None => done(ERROR_FILE_NOT_FOUND),
            }
        }
        // NumEntries then the rows at `Table`'s own offset, which includes the padding the SDK
        // puts after the count.
        IpHlpCall::GetIfTable2(out) => {
            let rows = offset_of!(MIB_IF_TABLE2, Table);
            let table = alloc_table(rows + nics.len().max(1) * size_of::<MIB_IF_ROW2>());
            unsafe {
                (*table.cast::<MIB_IF_TABLE2>()).NumEntries = nics.len() as u32;
                let first = table.add(rows).cast::<MIB_IF_ROW2>();
                for (i, nic) in nics.iter().enumerate() {
                    fill_row(&mut *first.add(i), nic);
                }
                *out = table;
            }
            done(ERROR_SUCCESS)
        }
        // Family must be AF_UNSPEC, AF_INET or AF_INET6, else ERROR_INVALID_PARAMETER
        // (Microsoft Learn: GetUnicastIpAddressTable). Lifetimes of 0xffffffff are infinite
        // (Microsoft Learn: MIB_UNICASTIPADDRESS_ROW); the addresses are static, manual and
        // DAD-preferred. An empty table is ERROR_SUCCESS with no rows here, where the page lists
        // ERROR_NOT_FOUND.
        IpHlpCall::GetUnicastIpAddressTable { family, table: out } => {
            if !matches!(family, 0 | AF_INET | AF_INET6) {
                return done(ERROR_INVALID_PARAMETER);
            }
            let entries: Vec<(&NicSnapshot, &crate::netif::IpNet)> = nics
                .iter()
                .flat_map(|n| live_addresses(n).map(move |a| (n, a)))
                .filter(|(_, a)| family_matches(family as u32, a.addr))
                .collect();
            let rows = offset_of!(MIB_UNICASTIPADDRESS_TABLE, Table);
            let table =
                alloc_table(rows + entries.len().max(1) * size_of::<MIB_UNICASTIPADDRESS_ROW>());
            unsafe {
                (*table.cast::<MIB_UNICASTIPADDRESS_TABLE>()).NumEntries = entries.len() as u32;
                let first = table.add(rows).cast::<MIB_UNICASTIPADDRESS_ROW>();
                for (i, (nic, net)) in entries.iter().enumerate() {
                    let row = &mut *first.add(i);
                    row.Address = sockaddr_inet(net.addr, nic.index);
                    row.InterfaceLuid.Value = luid(nic);
                    row.InterfaceIndex = nic.index;
                    row.PrefixOrigin = IpPrefixOriginManual;
                    row.SuffixOrigin = IpSuffixOriginManual;
                    row.ValidLifetime = u32::MAX;
                    row.PreferredLifetime = u32::MAX;
                    row.OnLinkPrefixLength = net.prefix;
                    row.DadState = IpDadStatePreferred;
                }
                *out = table;
            }
            done(ERROR_SUCCESS)
        }
        IpHlpCall::FreeMibTable(p) => free_table(p).then_some(NetResult::Ok(0)),
        IpHlpCall::UdpStatistics {
            family,
            stats,
            wide,
        } => unsafe { statistics(shared, true, family, stats, wide) },
        IpHlpCall::TcpStatistics {
            family,
            stats,
            wide,
        } => unsafe { statistics(shared, false, family, stats, wide) },
        // Measure, then lay out only into a buffer that fits: a null or short one gets
        // ERROR_BUFFER_OVERFLOW with the size needed (Microsoft Learn: GetAdaptersAddresses).
        IpHlpCall::GetAdaptersAddresses {
            family,
            flags,
            addresses,
            size,
        } => {
            if !matches!(family as u16, 0 | AF_INET | AF_INET6) {
                return done(ERROR_INVALID_PARAMETER);
            }
            let needed = adapters(&nics, family, flags, None);
            let have = unsafe { *size } as usize;
            if addresses.is_null() || have < needed {
                unsafe { *size = needed as u32 };
                return done(ERROR_BUFFER_OVERFLOW);
            }
            adapters(&nics, family, flags, Some(addresses));
            done(ERROR_SUCCESS)
        }
        // A nonzero LUID pins the interface, else a nonzero index; an unknown one is
        // ERROR_FILE_NOT_FOUND, and a destination that is not IPv4/IPv6 ERROR_INVALID_PARAMETER
        // (Microsoft Learn: GetBestRoute2). No route is ERROR_NETWORK_UNREACHABLE, which the page
        // does not list; snare's choice. The pinned interface is validated but routing still
        // follows the sim's own lookup, and with neither LUID nor index set the sim still routes,
        // where the page says at least one must be.
        IpHlpCall::GetBestRoute2 {
            luid: wanted_luid,
            index,
            source,
            destination,
            route,
            best_source,
            ..
        } => {
            let Some(dst) = read_inet(destination) else {
                return done(ERROR_INVALID_PARAMETER);
            };
            let src = (!source.is_null()).then(|| read_inet(source)).flatten();
            let src = src.filter(|ip| !ip.is_unspecified());
            let pinned = if !wanted_luid.is_null() && unsafe { wanted_luid.read_unaligned() } != 0 {
                Some(by_luid(unsafe { wanted_luid.read_unaligned() }).map(|n| n.index))
            } else if index != 0 {
                Some(by_index(index).map(|n| n.index))
            } else {
                None
            };
            if pinned == Some(None) {
                return done(ERROR_FILE_NOT_FOUND);
            }
            let Ok(choice) = shared.route_lookup(src, dst) else {
                return done(ERROR_NETWORK_UNREACHABLE);
            };
            let Some(nic) = by_index(choice.index) else {
                return done(ERROR_NETWORK_UNREACHABLE);
            };
            // The route that carried it, for its prefix, metric and kind; with none (the
            // destination is the host itself) the row is a host route. A gatewayless metric-0
            // route is an on-link one the stack made, MIB_IPPROTO_LOCAL; anything else is
            // MIB_IPPROTO_NETMGMT, a configured route (Microsoft Learn: MIB_IPFORWARD_ROW2).
            let matched = shared
                .live_routes()
                .into_iter()
                .filter(|(r, i)| *i == choice.index && r.dest.contains(dst))
                .max_by_key(|(r, _)| r.dest.prefix);
            let row = unsafe { &mut *route.cast::<MIB_IPFORWARD_ROW2>() };
            *row = unsafe { zeroed() };
            row.InterfaceLuid.Value = luid(nic);
            row.InterfaceIndex = nic.index;
            let (prefix, metric, connected) = match &matched {
                Some((r, _)) => (
                    crate::netif::IpNet::new(r.dest.network(), r.dest.prefix),
                    r.metric,
                    r.gateway.is_none() && r.metric == 0,
                ),
                None => (crate::netif::IpNet::host(dst), 0, true),
            };
            row.DestinationPrefix.Prefix = sockaddr_inet(prefix.addr, nic.index);
            row.DestinationPrefix.PrefixLength = prefix.prefix;
            let unspecified = if dst.is_ipv4() {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            } else {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            };
            row.NextHop = sockaddr_inet(choice.gateway.unwrap_or(unspecified), nic.index);
            // 0xffffffff is infinite (Microsoft Learn: MIB_IPFORWARD_ROW2).
            row.ValidLifetime = u32::MAX;
            row.PreferredLifetime = u32::MAX;
            row.Metric = metric;
            row.Protocol = if connected {
                MIB_IPPROTO_LOCAL
            } else {
                MIB_IPPROTO_NETMGMT
            };
            row.Loopback = nic.loopback;
            row.Origin = NlroManual;
            unsafe {
                *best_source.cast::<SOCKADDR_INET>() =
                    sockaddr_inet(choice.src.unwrap_or(unspecified), nic.index)
            };
            done(ERROR_SUCCESS)
        }
    }
}

/// `ConvertInterfaceNameToLuidA`/`W` once the name is decoded: writes the LUID it stands for, or
/// returns `ERROR_INVALID_NAME` for one that is not a valid NDIS name (or did not decode)
/// ([Microsoft Learn: ConvertInterfaceNameToLuidA](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacenametoluida)).
///
/// # Safety
/// `out` is null-checked by the hook and points to the caller's `NET_LUID`.
unsafe fn name_to_luid(name: Option<&str>, out: *mut u64) -> Option<NetResult> {
    match name.and_then(parse_luid_name) {
        Some(l) => {
            unsafe { out.write_unaligned(l) };
            done(ERROR_SUCCESS)
        }
        None => done(ERROR_INVALID_NAME),
    }
}

/// Lays the `IP_ADAPTER_ADDRESSES` list out from `base` (or only measures it, with `None`),
/// returning the bytes it takes.
///
/// Each adapter is an 8-aligned `IP_ADAPTER_ADDRESSES_LH` followed by its strings (the GUID
/// adapter name, friendly name, description and an empty DNS suffix) and its unicast entries,
/// each with its `SOCKADDR_IN`/`SOCKADDR_IN6`; `Next` and `FirstUnicastAddress` link them in
/// interface order, all pointing inside the caller's buffer. The measuring and writing passes
/// make the same sequence of `reserve` calls, so the offsets the second writes at are the ones the
/// first counted; keep any change to the layout in both. `Length` is the structure's size, which
/// callers read to tell its version
/// ([Microsoft Learn: IP_ADAPTER_ADDRESSES_LH](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh)).
fn adapters(nics: &[NicSnapshot], family: u32, flags: u32, base: Option<*mut u8>) -> usize {
    let mut at = 0usize;
    let mut reserve = |len: usize, align: usize| -> usize {
        at = at.next_multiple_of(align);
        let here = at;
        at += len;
        here
    };
    let ptr = |off: usize| base.map_or(std::ptr::null_mut(), |b| unsafe { b.add(off) });
    let mut prev: *mut IP_ADAPTER_ADDRESSES_LH = std::ptr::null_mut();
    for nic in nics {
        let rec = reserve(size_of::<IP_ADAPTER_ADDRESSES_LH>(), 8);
        let g = guid(nic);
        let adapter_name = format!("{}\0", guid_string(&g));
        let name_off = reserve(adapter_name.len(), 1);
        let friendly = wide(&nic.spec.name);
        let friendly_off = reserve(friendly.len() * 2, 2);
        let desc = wide(&description(nic));
        let desc_off = reserve(desc.len() * 2, 2);
        let suffix_off = reserve(2, 2);
        let addrs: Vec<&crate::netif::IpNet> = if flags & GAA_FLAG_SKIP_UNICAST != 0 {
            Vec::new()
        } else {
            live_addresses(nic)
                .filter(|a| family_matches(family, a.addr))
                .collect()
        };
        let mut unicast = Vec::new();
        for net in &addrs {
            let entry = reserve(size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>(), 8);
            let sa_len = if net.addr.is_ipv4() {
                size_of::<SOCKADDR_IN>()
            } else {
                size_of::<SOCKADDR_IN6>()
            };
            let sa = reserve(sa_len, 8);
            unicast.push((entry, sa, sa_len, *net));
        }
        let Some(_) = base else {
            continue;
        };
        unsafe {
            let a = &mut *ptr(rec).cast::<IP_ADAPTER_ADDRESSES_LH>();
            *a = zeroed();
            a.Anonymous1.Anonymous.Length = size_of::<IP_ADAPTER_ADDRESSES_LH>() as u32;
            a.Anonymous1.Anonymous.IfIndex = nic.index;
            std::ptr::copy_nonoverlapping(adapter_name.as_ptr(), ptr(name_off), adapter_name.len());
            a.AdapterName = ptr(name_off);
            std::ptr::copy_nonoverlapping(
                friendly.as_ptr(),
                ptr(friendly_off).cast(),
                friendly.len(),
            );
            a.FriendlyName = ptr(friendly_off).cast();
            std::ptr::copy_nonoverlapping(desc.as_ptr(), ptr(desc_off).cast(), desc.len());
            a.Description = ptr(desc_off).cast();
            *ptr(suffix_off).cast::<u16>() = 0;
            a.DnsSuffix = ptr(suffix_off).cast();
            if !nic.loopback {
                a.PhysicalAddress[..6].copy_from_slice(&nic.hw_addr());
                a.PhysicalAddressLength = 6;
            }
            a.Mtu = nic.spec.mtu;
            a.IfType = if nic.loopback {
                IF_TYPE_SOFTWARE_LOOPBACK
            } else {
                IF_TYPE_ETHERNET_CSMACD
            };
            a.OperStatus = oper_status(nic);
            a.Ipv6IfIndex = nic.index;
            a.TransmitLinkSpeed = speed(nic);
            a.ReceiveLinkSpeed = speed(nic);
            a.Luid.Value = luid(nic);
            a.ConnectionType = NET_IF_CONNECTION_DEDICATED;
            let mut last: *mut IP_ADAPTER_UNICAST_ADDRESS_LH = std::ptr::null_mut();
            for (entry, sa, sa_len, net) in &unicast {
                let u = &mut *ptr(*entry).cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
                *u = zeroed();
                u.Anonymous.Anonymous.Length = size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>() as u32;
                let inet = sockaddr_inet(net.addr, nic.index);
                std::ptr::copy_nonoverlapping(
                    (&inet as *const SOCKADDR_INET).cast::<u8>(),
                    ptr(*sa),
                    *sa_len,
                );
                u.Address.lpSockaddr = ptr(*sa).cast::<SOCKADDR>();
                u.Address.iSockaddrLength = *sa_len as i32;
                u.PrefixOrigin = IpPrefixOriginManual;
                u.SuffixOrigin = IpSuffixOriginManual;
                u.DadState = IpDadStatePreferred;
                u.ValidLifetime = u32::MAX;
                u.PreferredLifetime = u32::MAX;
                u.LeaseLifetime = u32::MAX;
                u.OnLinkPrefixLength = net.prefix;
                if last.is_null() {
                    a.FirstUnicastAddress = u;
                } else {
                    (*last).Next = u;
                }
                last = u;
            }
            if !prev.is_null() {
                (*prev).Next = a;
            }
            prev = a;
        }
    }
    at
}
