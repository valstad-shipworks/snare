#![cfg(windows)]

//! IP Helper enumeration answers from the sim's topology: the alias/LUID/index conversions,
//! `GetIfEntry2`, the unicast address table, `GetAdaptersAddresses` and `GetBestRoute2`.

use std::mem::zeroed;
use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::ptr;

use snare::{IpNet, NicSpec, Sim};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, ConvertInterfaceIndexToLuid, ConvertInterfaceLuidToAlias,
    ConvertInterfaceLuidToIndex, ConvertInterfaceLuidToNameA, ConvertInterfaceNameToLuidA,
    FreeMibTable, GetAdaptersAddresses, GetBestRoute2, GetIfEntry2, GetIfTable2,
    GetUnicastIpAddressTable, IP_ADAPTER_ADDRESSES_LH, MIB_IF_ROW2, MIB_IF_TABLE2,
    MIB_IPFORWARD_ROW2, MIB_UNICASTIPADDRESS_TABLE, if_indextoname, if_nametoindex,
};
use windows_sys::Win32::NetworkManagement::Ndis::{
    IfOperStatusDown, IfOperStatusUp, MediaConnectStateConnected, MediaConnectStateDisconnected,
    NET_LUID_LH,
};
use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_UNSPEC, SOCKADDR_INET};

const ERROR_SUCCESS: u32 = 0;
const ERROR_BUFFER_OVERFLOW: u32 = 111;

fn net(s: &str) -> IpNet {
    s.parse().unwrap()
}

fn sim() -> Sim {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address(net("10.0.0.1/24"))
                .station("10.0.0.2".parse::<IpAddr>().unwrap())
                .mtu(9000),
        )
        .build()
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn alias_luid(alias: &str) -> Result<NET_LUID_LH, u32> {
    let mut luid: NET_LUID_LH = unsafe { zeroed() };
    match unsafe { ConvertInterfaceAliasToLuid(wide(alias).as_ptr(), &mut luid) } {
        ERROR_SUCCESS => Ok(luid),
        e => Err(e),
    }
}

fn if_row(luid: NET_LUID_LH) -> MIB_IF_ROW2 {
    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceLuid = luid;
    assert_eq!(unsafe { GetIfEntry2(&mut row) }, ERROR_SUCCESS);
    row
}

fn alias_of(luid: NET_LUID_LH) -> String {
    let mut alias = [0u16; 257];
    assert_eq!(
        unsafe { ConvertInterfaceLuidToAlias(&luid, alias.as_mut_ptr(), alias.len()) },
        ERROR_SUCCESS
    );
    let end = alias.iter().position(|&c| c == 0).unwrap();
    String::from_utf16(&alias[..end]).unwrap()
}

#[test]
fn physical_medium_profiles_match_entry_and_table() {
    for deterministic in [false, true] {
        let builder = Sim::builder()
            .nic(NicSpec::new("default-medium").index(4))
            .nic(
                NicSpec::new("unspecified-medium")
                    .index(5)
                    .physical_medium(0),
            )
            .nic(NicSpec::new("ethernet-medium").index(6).physical_medium(14));
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
            assert_eq!(unsafe { GetIfTable2(&mut table) }, ERROR_SUCCESS);
            let rows = unsafe {
                std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
            };
            let loopback = rows.iter().find(|row| row.InterfaceIndex == 1).unwrap();
            assert_eq!(loopback.PhysicalMediumType, 0);
            for (alias, expected) in [
                ("default-medium", 14),
                ("unspecified-medium", 0),
                ("ethernet-medium", 14),
            ] {
                let entry = if_row(alias_luid(alias).unwrap());
                let listed = rows
                    .iter()
                    .find(|row| row.InterfaceIndex == entry.InterfaceIndex)
                    .unwrap();
                assert_eq!(entry.PhysicalMediumType, expected);
                assert_eq!(listed.PhysicalMediumType, expected);
                assert_eq!(listed.MediaType, entry.MediaType);
                assert_eq!(snare::nic(alias).unwrap().physical_medium(), expected);
            }
            unsafe { FreeMibTable(table.cast()) };
            snare::set_nic("unspecified-medium", |spec| spec.physical_medium = Some(14)).unwrap();
            assert_eq!(
                if_row(alias_luid("unspecified-medium").unwrap()).PhysicalMediumType,
                14
            );
        });
    }
}

/// The calls fast-talker's Windows NIC lookup makes: alias to LUID, the unicast table to find the
/// interface by address, LUID back to alias, and `GetIfEntry2` for state and counters.
#[test]
fn fast_talker_lookup_calls() {
    sim().run(|| {
        let luid = alias_luid("eth0").unwrap();
        let mut table: *mut MIB_UNICASTIPADDRESS_TABLE = ptr::null_mut();
        assert_eq!(
            unsafe { GetUnicastIpAddressTable(AF_UNSPEC, &mut table) },
            ERROR_SUCCESS
        );
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let row = rows
            .iter()
            .find(|r| unsafe { r.Address.si_family } == AF_INET && unsafe {
                r.Address.Ipv4.sin_addr.S_un.S_addr
            } == u32::from_ne_bytes([10, 0, 0, 1]))
            .expect("10.0.0.1 in the unicast table");
        assert_eq!(row.InterfaceIndex, 4);
        assert_eq!(unsafe { row.InterfaceLuid.Value }, unsafe { luid.Value });
        assert_eq!(row.OnLinkPrefixLength, 24);
        let found = row.InterfaceLuid;
        unsafe { FreeMibTable(table.cast()) };
        assert_eq!(alias_of(found), "eth0");

        let row = if_row(luid);
        assert_eq!(row.InterfaceIndex, 4);
        assert_eq!(row.Mtu, 9000);
        assert_eq!(row.PhysicalAddressLength, 6);
        assert_eq!(&row.PhysicalAddress[..6], &[2, 0, 0, 0, 0, 4]);
        assert_eq!(row.OperStatus, IfOperStatusUp);
        assert_eq!(row.MediaConnectState, MediaConnectStateConnected);
        let before = row.OutOctets;

        let station = UdpSocket::bind("10.0.0.2:7000").unwrap();
        let sock = UdpSocket::bind("10.0.0.1:0").unwrap();
        sock.send_to(&[0; 100], "10.0.0.2:7000").unwrap();
        let mut buf = [0u8; 200];
        station.recv_from(&mut buf).unwrap();
        let row = if_row(luid);
        assert_eq!(row.OutOctets, before + 142);
        assert_eq!(row.OutOctets, snare::nic_counters("eth0").unwrap().tx_bytes);

        snare::set_link("eth0", false).unwrap();
        let row = if_row(luid);
        assert_eq!(row.OperStatus, IfOperStatusDown);
        assert_eq!(row.MediaConnectState, MediaConnectStateDisconnected);

        let mut table: *mut MIB_IF_TABLE2 = ptr::null_mut();
        assert_eq!(unsafe { GetIfTable2(&mut table) }, ERROR_SUCCESS);
        let rows = unsafe {
            std::slice::from_raw_parts((*table).Table.as_ptr(), (*table).NumEntries as usize)
        };
        let indices: Vec<u32> = rows.iter().map(|r| r.InterfaceIndex).collect();
        unsafe { FreeMibTable(table.cast()) };
        assert_eq!(indices, vec![1, 2, 4]);
    });
}

#[test]
fn adapters_addresses_buffer_protocol() {
    sim().run(|| {
        let mut size = 0u32;
        let rc = unsafe {
            GetAdaptersAddresses(AF_UNSPEC as u32, 0, ptr::null(), ptr::null_mut(), &mut size)
        };
        assert_eq!(rc, ERROR_BUFFER_OVERFLOW);
        assert!(size as usize > std::mem::size_of::<IP_ADAPTER_ADDRESSES_LH>());
        let mut small = vec![0u64; 4];
        let mut short = 32u32;
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_UNSPEC as u32,
                0,
                ptr::null(),
                small.as_mut_ptr().cast(),
                &mut short,
            )
        };
        assert_eq!(rc, ERROR_BUFFER_OVERFLOW);
        assert_eq!(short, size);

        let mut buf = vec![0u64; size as usize / 8 + 1];
        let rc = unsafe {
            GetAdaptersAddresses(
                AF_INET as u32,
                0,
                ptr::null(),
                buf.as_mut_ptr().cast(),
                &mut size,
            )
        };
        assert_eq!(rc, ERROR_SUCCESS);
        let mut seen = Vec::new();
        let mut cur = buf.as_ptr() as *const IP_ADAPTER_ADDRESSES_LH;
        while !cur.is_null() {
            let a = unsafe { &*cur };
            let friendly = unsafe {
                let mut len = 0;
                while *a.FriendlyName.add(len) != 0 {
                    len += 1;
                }
                String::from_utf16(std::slice::from_raw_parts(a.FriendlyName, len)).unwrap()
            };
            let mut addrs = Vec::new();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let sa = unsafe { (*u).Address.lpSockaddr } as *const SOCKADDR_INET;
                let raw = unsafe { (*sa).Ipv4.sin_addr.S_un.S_addr };
                addrs.push(Ipv4Addr::from(raw.to_ne_bytes()));
                u = unsafe { (*u).Next };
            }
            seen.push((
                unsafe { a.Anonymous1.Anonymous.IfIndex },
                friendly,
                a.Mtu,
                addrs,
            ));
            cur = a.Next;
        }
        let eth0 = seen.iter().find(|s| s.1 == "eth0").unwrap();
        assert_eq!((eth0.0, eth0.2), (4, 9000));
        assert_eq!(eth0.3, vec![Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(seen[0].0, 1, "loopback first");
    });
}

#[test]
fn if_nametoindex_and_best_route() {
    sim().run(|| {
        let luid = alias_luid("eth0").unwrap();
        let mut name = [0u8; 256];
        assert_eq!(
            unsafe { ConvertInterfaceLuidToNameA(&luid, name.as_mut_ptr(), name.len()) },
            ERROR_SUCCESS
        );
        let end = name.iter().position(|&c| c == 0).unwrap();
        let text = std::str::from_utf8(&name[..end]).unwrap().to_string();
        assert_eq!(text, format!("ethernet_{}", 32768 + 4));
        assert_eq!(unsafe { if_nametoindex(name.as_ptr()) }, 4);
        let mut back: NET_LUID_LH = unsafe { zeroed() };
        assert_eq!(
            unsafe { ConvertInterfaceNameToLuidA(name.as_ptr(), &mut back) },
            ERROR_SUCCESS
        );
        assert_eq!(unsafe { back.Value }, unsafe { luid.Value });
        let mut out = [0u8; 256];
        let p = unsafe { if_indextoname(4, out.as_mut_ptr()) };
        assert!(!p.is_null());
        assert_eq!(&out[..end], text.as_bytes());
        assert!(unsafe { if_indextoname(4, ptr::null_mut()) }.is_null());

        let mut index = 0;
        assert_eq!(
            unsafe { ConvertInterfaceLuidToIndex(&luid, &mut index) },
            ERROR_SUCCESS
        );
        assert_eq!(index, 4);
        let mut again: NET_LUID_LH = unsafe { zeroed() };
        assert_eq!(
            unsafe { ConvertInterfaceIndexToLuid(4, &mut again) },
            ERROR_SUCCESS
        );
        assert_eq!(unsafe { again.Value }, unsafe { luid.Value });

        let mut dst: SOCKADDR_INET = unsafe { zeroed() };
        dst.si_family = AF_INET;
        dst.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([10, 0, 0, 2]);
        let mut route: MIB_IPFORWARD_ROW2 = unsafe { zeroed() };
        let mut src: SOCKADDR_INET = unsafe { zeroed() };
        let rc =
            unsafe { GetBestRoute2(ptr::null(), 0, ptr::null(), &dst, 0, &mut route, &mut src) };
        assert_eq!(rc, ERROR_SUCCESS);
        assert_eq!(route.InterfaceIndex, 4);
        assert_eq!(route.DestinationPrefix.PrefixLength, 24);
        assert_eq!(
            unsafe { src.Ipv4.sin_addr.S_un.S_addr },
            u32::from_ne_bytes([10, 0, 0, 1])
        );
    });
}

/// The codes the real IP Helper returns for an interface that does not exist, compared against
/// the sim's for the same calls.
#[test]
fn not_found_codes_pinned() {
    let probe = || {
        let mut luid: NET_LUID_LH = unsafe { zeroed() };
        let alias = unsafe { ConvertInterfaceAliasToLuid(wide("snare-nope").as_ptr(), &mut luid) };
        let name = unsafe { ConvertInterfaceNameToLuidA(c"snarenope".as_ptr().cast(), &mut luid) };
        let index_to_luid = unsafe { ConvertInterfaceIndexToLuid(0x00ff_fff0, &mut luid) };
        let bogus = NET_LUID_LH {
            Value: (6u64 << 48) | (0x00ff_fff0u64 << 24),
        };
        let mut index = 0;
        let luid_to_index = unsafe { ConvertInterfaceLuidToIndex(&bogus, &mut index) };
        let mut alias_buf = [0u16; 257];
        let luid_to_alias =
            unsafe { ConvertInterfaceLuidToAlias(&bogus, alias_buf.as_mut_ptr(), alias_buf.len()) };
        let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
        row.InterfaceIndex = 0x00ff_fff0;
        let entry = unsafe { GetIfEntry2(&mut row) };
        let to_index = unsafe { if_nametoindex(c"snarenope".as_ptr().cast()) };
        let mut buf = [0u8; 256];
        let to_name = unsafe { if_indextoname(0x00ff_fff0, buf.as_mut_ptr()) }.is_null();
        (
            alias,
            name,
            index_to_luid,
            luid_to_index,
            luid_to_alias,
            entry,
            to_index,
            to_name,
        )
    };
    let real = snare::real(probe);
    let simulated = sim().run(probe);
    assert_eq!(simulated, real);
}
