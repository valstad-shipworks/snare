#![cfg(windows)]

//! The real machine's IP Helper answers for a real adapter against the sim's IP Helper model
//! (src/iphlp.rs) for a sim interface mirroring it (same alias, index, MTU, MAC, speed, link
//! state and addresses): `GetAdaptersAddresses` (the sizing call's `ERROR_BUFFER_OVERFLOW`, then
//! the adapter's type, status, MTU, physical address length and unicast addresses with their
//! prefixes), `GetIfEntry2` and `GetIfTable2` (the row fields the model fills, an unknown LUID's
//! code), and `GetUdpStatistics`/`GetUdpStatisticsEx`/`GetUdpStatisticsEx2` (status codes; the
//! counters belong to each world's own traffic). Fields the model leaves to a later model
//! (description, interface GUID, the adapter's counters, DHCP and DNS data) are reported as notes,
//! not asserted.
//!
//! References: [Microsoft Learn: GetAdaptersAddresses](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses);
//! [Microsoft Learn: IP_ADAPTER_ADDRESSES_LH](https://learn.microsoft.com/en-us/windows/win32/api/iptypes/ns-iptypes-ip_adapter_addresses_lh);
//! [Microsoft Learn: GetIfEntry2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getifentry2);
//! [Microsoft Learn: GetIfTable2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getiftable2);
//! [Microsoft Learn: MIB_IF_ROW2](https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_if_row2);
//! [Microsoft Learn: GetUdpStatisticsEx2](https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getudpstatisticsex2).

#[path = "support/hw.rs"]
mod hw;

use std::mem::zeroed;
use std::net::IpAddr;
use std::ptr;

use hw::need;
use snare::{IpNet, NicSpec, Sim};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER, GAA_FLAG_SKIP_MULTICAST,
    GetAdaptersAddresses, GetIfEntry2, GetIfTable2, GetUdpStatistics, GetUdpStatisticsEx,
    GetUdpStatisticsEx2, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IF_TABLE2, MIB_UDPSTATS,
    MIB_UDPSTATS2,
};
use windows_sys::Win32::NetworkManagement::Ndis::IfOperStatusUp;
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};

const NEEDS_ADAPTER: &str = "needs a wired adapter (set SNARE_HW_WIN_ADAPTER=<alias>)";

const FLAGS: u32 = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;

fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

unsafe fn sockaddr_ip(sa: *const u8) -> Option<IpAddr> {
    let family = unsafe { sa.cast::<u16>().read_unaligned() };
    match family {
        AF_INET => {
            let sin = unsafe { sa.cast::<SOCKADDR_IN>().read_unaligned() };
            Some(IpAddr::from(
                unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes(),
            ))
        }
        AF_INET6 => {
            let sin6 = unsafe { sa.cast::<SOCKADDR_IN6>().read_unaligned() };
            Some(IpAddr::from(unsafe { sin6.sin6_addr.u.Byte }))
        }
        _ => None,
    }
}

/// One adapter of `GetAdaptersAddresses`, reduced to the fields the model fills, plus the ones it
/// does not (kept apart for notes).
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdapterShape {
    length: u32,
    if_index: u32,
    if_type: u32,
    oper_status: i32,
    mtu: u32,
    physical_len: u32,
    transmit_speed: u64,
    unicast: Vec<(IpAddr, u8)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AdapterExtra {
    description: String,
    dhcp_enabled: bool,
    ipv4_metric: u32,
}

/// `GetAdaptersAddresses(AF_UNSPEC)`: the sizing call's code and whether it named a size, then the
/// adapter called `alias`.
fn adapters(alias: &str) -> ((u32, bool), Option<(AdapterShape, AdapterExtra)>) {
    let mut len = 0u32;
    let sizing = unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            FLAGS,
            ptr::null(),
            ptr::null_mut(),
            &mut len,
        )
    };
    let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
    let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    if unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, FLAGS, ptr::null(), first, &mut len) } != 0 {
        return ((sizing, len > 0), None);
    }
    let mut at = first as *const IP_ADAPTER_ADDRESSES_LH;
    while !at.is_null() {
        let a = unsafe { &*at };
        if wide_str(a.FriendlyName) == alias {
            let mut unicast = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let e = unsafe { &*u };
                if let Some(ip) = unsafe { sockaddr_ip(e.Address.lpSockaddr.cast()) } {
                    unicast.push((ip, e.OnLinkPrefixLength));
                }
                u = e.Next;
            }
            unicast.sort();
            let shape = AdapterShape {
                length: unsafe { a.Anonymous1.Anonymous.Length },
                if_index: unsafe { a.Anonymous1.Anonymous.IfIndex },
                if_type: a.IfType,
                oper_status: a.OperStatus,
                mtu: a.Mtu,
                physical_len: a.PhysicalAddressLength,
                transmit_speed: a.TransmitLinkSpeed,
                unicast,
            };
            let extra = AdapterExtra {
                description: wide_str(a.Description),
                dhcp_enabled: unsafe { a.Anonymous2.Flags } & 0x4 != 0,
                ipv4_metric: a.Ipv4Metric,
            };
            return ((sizing, len > 0), Some((shape, extra)));
        }
        at = a.Next;
    }
    ((sizing, len > 0), None)
}

/// The `MIB_IF_ROW2` fields the model fills.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RowShape {
    index: u32,
    if_type: u32,
    media_type: i32,
    physical_medium: i32,
    access_type: i32,
    connection_type: i32,
    oper_status: i32,
    admin_status: i32,
    media_connect: i32,
    mtu: u32,
    physical_len: u32,
    transmit_speed: u64,
}

fn row_shape(r: &MIB_IF_ROW2) -> RowShape {
    RowShape {
        index: r.InterfaceIndex,
        if_type: r.Type,
        media_type: r.MediaType,
        physical_medium: r.PhysicalMediumType,
        access_type: r.AccessType,
        connection_type: r.ConnectionType,
        oper_status: r.OperStatus,
        admin_status: r.AdminStatus,
        media_connect: r.MediaConnectState,
        mtu: r.Mtu,
        physical_len: r.PhysicalAddressLength,
        transmit_speed: r.TransmitLinkSpeed,
    }
}

/// `GetIfEntry2` by `index`, an unknown LUID's code, and the row `GetIfTable2` lists for it.
fn rows(index: u32) -> (Result<RowShape, u32>, u32, Result<Option<RowShape>, u32>) {
    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceIndex = index;
    let entry = match unsafe { GetIfEntry2(&mut row) } {
        0 => Ok(row_shape(&row)),
        rc => Err(rc),
    };
    let mut bogus: MIB_IF_ROW2 = unsafe { zeroed() };
    bogus.InterfaceLuid.Value = (6u64 << 48) | (0x00ff_fffe << 24);
    let unknown = unsafe { GetIfEntry2(&mut bogus) };
    let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
    let listed = match unsafe { GetIfTable2(&mut table) } {
        0 => {
            let t = unsafe { &*table };
            let rows =
                unsafe { std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize) };
            let found = rows
                .iter()
                .find(|r| r.InterfaceIndex == index)
                .map(row_shape);
            unsafe { FreeMibTable(table.cast()) };
            Ok(found)
        }
        rc => Err(rc),
    };
    (entry, unknown, listed)
}

/// The three UDP statistics calls' codes, for IPv4 and IPv6 where the call takes a family.
fn udp_codes() -> Vec<u32> {
    let mut s: MIB_UDPSTATS = unsafe { zeroed() };
    let mut s2: MIB_UDPSTATS2 = unsafe { zeroed() };
    vec![
        unsafe { GetUdpStatistics(&mut s) },
        unsafe { GetUdpStatisticsEx(&mut s, AF_INET as u32) },
        unsafe { GetUdpStatisticsEx(&mut s, AF_INET6 as u32) },
        unsafe { GetUdpStatisticsEx2(&mut s2, AF_INET as u32) },
        unsafe { GetUdpStatisticsEx(&mut s, 99) },
    ]
}

/// The real adapter as a sim interface.
fn sim_for(alias: &str, shape: &AdapterShape, mac_len: u32, physical_medium: Option<i32>) -> Sim {
    let mut spec = NicSpec::new(alias)
        .index(shape.if_index)
        .mtu(shape.mtu)
        .link(shape.oper_status == IfOperStatusUp);
    spec.speed_mbps = u32::try_from(shape.transmit_speed / 1_000_000).ok();
    spec.physical_medium = physical_medium;
    for (ip, prefix) in &shape.unicast {
        spec = spec.address(IpNet::new(*ip, *prefix));
    }
    if mac_len != 6 {
        hw::note(&format!(
            "{alias} has a {mac_len}-byte physical address; the sim's are 6"
        ));
    }
    Sim::builder().nic(spec).build()
}

#[test]
#[ignore = "hardware: needs a wired adapter"]
fn hw_win_adapters_addresses_match() {
    let alias = need!(hw::hw().win_adapter.clone(), "{NEEDS_ADAPTER}");
    let (real_sizing, real) = snare::real(|| adapters(&alias));
    let (real_shape, real_extra) = need!(real, "GetAdaptersAddresses does not list {alias}");
    let sim = sim_for(&alias, &real_shape, real_shape.physical_len, None);
    let (sim_sizing, simulated) = sim.run(|| adapters(&alias));
    let (sim_shape, sim_extra) = simulated.expect("the sim lists its interface");
    eprintln!("{alias}: {real_shape:#?} {real_extra:?}");
    assert_eq!(sim_sizing, real_sizing, "sizing call: (code, size named)");
    assert_eq!(sim_shape, real_shape, "IP_ADAPTER_ADDRESSES_LH");
    if sim_extra != real_extra {
        hw::note(&format!(
            "not modelled: real {real_extra:?}, sim {sim_extra:?}"
        ));
    }
}

#[test]
#[ignore = "hardware: needs a wired adapter"]
fn hw_win_if_rows_match() {
    let alias = need!(hw::hw().win_adapter.clone(), "{NEEDS_ADAPTER}");
    let (_, real) = snare::real(|| adapters(&alias));
    let (shape, _) = need!(real, "GetAdaptersAddresses does not list {alias}");
    let index = shape.if_index;
    let real_rows = snare::real(|| rows(index));
    let physical_medium = real_rows
        .0
        .as_ref()
        .expect("GetIfEntry2 lists the measured adapter")
        .physical_medium;
    let sim_rows =
        sim_for(&alias, &shape, shape.physical_len, Some(physical_medium)).run(|| rows(index));
    assert_eq!(sim_rows.0, real_rows.0, "GetIfEntry2({alias})");
    assert_eq!(sim_rows.1, real_rows.1, "GetIfEntry2 of an unknown LUID");
    assert_eq!(sim_rows.2, real_rows.2, "GetIfTable2's row for {alias}");
}

#[test]
fn hw_win_udp_statistics_codes_match() {
    let real = snare::real(udp_codes);
    let sim = Sim::new().run(udp_codes);
    assert_eq!(
        sim, real,
        "[GetUdpStatistics, Ex(AF_INET), Ex(AF_INET6), Ex2(AF_INET), Ex(99)]"
    );
}
