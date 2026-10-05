#![cfg(windows)]

//! A real network adapter's device node and registry keys against the sim's model of them
//! (src/win_adapter.rs): the adapter is found the way fast-talker's `nic/windows.rs` finds it
//! (the interface GUID from `GetIfEntry2`, then the `GUID_DEVCLASS_NET` device whose driver key's
//! `NetCfgInstanceId` matches), its standardized keywords and their `Ndi\Params\<keyword>\max`
//! are read, and a sim given an [`Adapter`] built from those values must answer the same probe
//! identically: the same keywords present, the same values and maxima, the same
//! `DriverVersion`, `ERROR_FILE_NOT_FOUND` for an absent keyword, and the same answer to opening
//! the driver key for writing (refused to a standard user's token). With
//! `SNARE_HW_MUTATE=1` and an elevated token it also writes a keyword and restarts the device on
//! both, restoring the real adapter after.
//!
//! References: [Microsoft Learn: Standardized INF Keywords for Network Devices](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/standardized-inf-keywords-for-network-devices);
//! [Microsoft Learn: Specifying Configuration Parameters for the Advanced Properties Page](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/specifying-configuration-parameters-for-the-advanced-properties-page);
//! [Microsoft Learn: SetupDiOpenDevRegKey](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey);
//! [Microsoft Learn: CM_Disable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode).

#[path = "support/hw.rs"]
mod hw;

use std::mem::{size_of, zeroed};
use std::net::IpAddr;
use std::ptr;
use std::time::Duration;

use hw::{need, require};
use snare::{Adapter, IpNet, NicSpec, Privileges, Sim};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DISABLE_UI_NOT_OK, CM_Disable_DevNode, CM_Enable_DevNode, DICS_FLAG_GLOBAL, DIGCF_PRESENT,
    DIREG_DRV, GUID_DEVCLASS_NET, HDEVINFO, SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList,
    SetupDiEnumDeviceInfo, SetupDiGetClassDevsW, SetupDiOpenDevRegKey,
};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, GetLastError, INVALID_HANDLE_VALUE};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, GetIfEntry2, IP_ADAPTER_ADDRESSES_LH,
    MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegOpenKeyExW,
    RegQueryValueExW, RegSetValueExW,
};
use windows_sys::core::GUID;

/// The standardized keywords probed: the ones `Adapter::new` models plus those fast-talker and
/// the driver crates tune.
const KEYWORDS: [&str; 14] = [
    "*ReceiveBuffers",
    "*TransmitBuffers",
    "*InterruptModeration",
    "*FlowControl",
    "*NumRssQueues",
    "*RSS",
    "*SoftwareTimestamp",
    "*PtpHardwareTimestamp",
    "*EEE",
    "*JumboPacket",
    "*SpeedDuplex",
    "*LsoV2IPv4",
    "*PriorityVLANTag",
    "*WakeOnMagicPacket",
];

/// The network class key: writable only with an elevated token.
const CLASS_KEY: &str =
    r"SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}";

const NEEDS_ADAPTER: &str = "needs a wired adapter (set SNARE_HW_WIN_ADAPTER=<alias>)";

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

fn guid_string(g: &GUID) -> String {
    let d = g.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        g.data1, g.data2, g.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

fn if_row(alias: &str) -> Result<MIB_IF_ROW2, u32> {
    let mut luid: NET_LUID_LH = unsafe { zeroed() };
    let rc = unsafe { ConvertInterfaceAliasToLuid(wide(alias).as_ptr(), &mut luid) };
    if rc != ERROR_SUCCESS {
        return Err(rc);
    }
    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceLuid = luid;
    match unsafe { GetIfEntry2(&mut row) } {
        ERROR_SUCCESS => Ok(row),
        rc => Err(rc),
    }
}

/// Whether the process token is elevated, judged by the class key's ACL, which grants writing
/// only to administrators running elevated.
fn elevated() -> bool {
    snare::real(|| {
        let path = wide(CLASS_KEY);
        let mut h: HKEY = ptr::null_mut();
        let rc = unsafe {
            RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                path.as_ptr(),
                0,
                KEY_READ | KEY_SET_VALUE,
                &mut h,
            )
        };
        if rc == ERROR_SUCCESS {
            unsafe { RegCloseKey(h) };
        }
        rc == ERROR_SUCCESS
    })
}

struct Device {
    set: HDEVINFO,
    data: SP_DEVINFO_DATA,
}

impl Device {
    /// The device node whose driver key's `NetCfgInstanceId` is `alias`'s interface GUID, or the
    /// error that stopped the search.
    fn find(alias: &str) -> Result<Device, u32> {
        let want = guid_string(&if_row(alias)?.InterfaceGuid);
        let set = unsafe {
            SetupDiGetClassDevsW(
                &GUID_DEVCLASS_NET,
                ptr::null(),
                ptr::null_mut(),
                DIGCF_PRESENT,
            )
        };
        if set == INVALID_HANDLE_VALUE as HDEVINFO {
            return Err(unsafe { GetLastError() });
        }
        let mut device = Device {
            set,
            data: unsafe { zeroed() },
        };
        for i in 0.. {
            device.data = unsafe { zeroed() };
            device.data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            if unsafe { SetupDiEnumDeviceInfo(set, i, &mut device.data) } == 0 {
                return Err(unsafe { GetLastError() });
            }
            let id = device
                .key(KEY_READ)
                .and_then(|k| k.string("NetCfgInstanceId"));
            if id.is_ok_and(|id| id.eq_ignore_ascii_case(&want)) {
                return Ok(device);
            }
        }
        unreachable!()
    }

    fn key(&self, access: u32) -> Result<Key, u32> {
        let h = unsafe {
            SetupDiOpenDevRegKey(self.set, &self.data, DICS_FLAG_GLOBAL, 0, DIREG_DRV, access)
        };
        if ptr::eq(h, INVALID_HANDLE_VALUE) {
            return Err(unsafe { GetLastError() });
        }
        Ok(Key(h))
    }

    fn restart(&self) -> (u32, u32) {
        let node = self.data.DevInst;
        (
            unsafe { CM_Disable_DevNode(node, CM_DISABLE_UI_NOT_OK) },
            unsafe { CM_Enable_DevNode(node, 0) },
        )
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        unsafe { SetupDiDestroyDeviceInfoList(self.set) };
    }
}

struct Key(HKEY);

impl Key {
    /// A `REG_SZ` value; another type is reported as `Err(0x8000_0000 | type)`.
    fn string(&self, name: &str) -> Result<String, u32> {
        let name = wide(name);
        let mut buf = [0u16; 512];
        let mut len = size_of::<[u16; 512]>() as u32;
        let mut typ = 0;
        let rc = unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                ptr::null(),
                &mut typ,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        };
        if rc != ERROR_SUCCESS {
            return Err(rc);
        }
        if typ != REG_SZ {
            return Err(0x8000_0000 | typ);
        }
        let units = &buf[..len as usize / 2];
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        Ok(String::from_utf16_lossy(&units[..end]))
    }

    fn set_string(&self, name: &str, value: &str) -> u32 {
        let name = wide(name);
        let value = wide(value);
        unsafe {
            RegSetValueExW(
                self.0,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                (value.len() * 2) as u32,
            )
        }
    }

    fn subkey(&self, path: &str) -> Result<Key, u32> {
        let path = wide(path);
        let mut h: HKEY = ptr::null_mut();
        match unsafe { RegOpenKeyExW(self.0, path.as_ptr(), 0, KEY_READ, &mut h) } {
            ERROR_SUCCESS => Ok(Key(h)),
            rc => Err(rc),
        }
    }

    /// The keyword's value and its `Ndi\Params` maximum, if it has one.
    fn keyword(&self, name: &str) -> Keyword {
        let value = self.string(name)?;
        let max = self
            .subkey(&format!(r"Ndi\Params\{name}"))
            .and_then(|k| k.string("max"))
            .ok()
            .and_then(|m| m.trim().parse().ok());
        Ok((value, max))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

/// A keyword's value and `Ndi\Params` maximum, or the registry error reading it.
type Keyword = Result<(String, Option<u32>), u32>;

/// What the read probe found for `alias`: the device found (or why not), `DriverVersion`, each
/// keyword's value and maximum or error, and the answer to opening the driver key for writing.
#[derive(Debug, PartialEq, Eq)]
struct Found {
    device: Result<(), u32>,
    driver_version: Result<String, u32>,
    keywords: Vec<(&'static str, Keyword)>,
    writable: Result<(), u32>,
}

fn probe(alias: &str) -> Found {
    let device = match Device::find(alias) {
        Ok(d) => d,
        Err(e) => {
            return Found {
                device: Err(e),
                driver_version: Err(0),
                keywords: Vec::new(),
                writable: Err(0),
            };
        }
    };
    let key = device
        .key(KEY_READ)
        .expect("the driver key opens for reading");
    Found {
        device: Ok(()),
        driver_version: key.string("DriverVersion"),
        keywords: KEYWORDS.iter().map(|&k| (k, key.keyword(k))).collect(),
        writable: device.key(KEY_READ | KEY_SET_VALUE).map(drop),
    }
}

/// The adapter as GetAdaptersAddresses reports it, as a sim interface of the same alias, index,
/// MTU, MAC, speed, link state and addresses.
fn nic_spec(alias: &str) -> Option<NicSpec> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut len = 0u32;
    unsafe {
        GetAdaptersAddresses(
            AF_UNSPEC as u32,
            flags,
            ptr::null(),
            ptr::null_mut(),
            &mut len,
        )
    };
    let mut buf = vec![0u64; (len as usize).div_ceil(8) + 1];
    let first = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    if unsafe { GetAdaptersAddresses(AF_UNSPEC as u32, flags, ptr::null(), first, &mut len) } != 0 {
        return None;
    }
    let mut at = first as *const IP_ADAPTER_ADDRESSES_LH;
    while !at.is_null() {
        let a = unsafe { &*at };
        if wide_str(a.FriendlyName) == alias {
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&a.PhysicalAddress[..6]);
            let mut spec = NicSpec::new(alias)
                .index(unsafe { a.Anonymous1.Anonymous.IfIndex })
                .mtu(a.Mtu)
                .mac(mac)
                .link(a.OperStatus == IfOperStatusUp);
            spec.speed_mbps = u32::try_from(a.TransmitLinkSpeed / 1_000_000).ok();
            let mut u = a.FirstUnicastAddress;
            while !u.is_null() {
                let entry = unsafe { &*u };
                if let Some(ip) = unsafe { sockaddr_ip(entry.Address.lpSockaddr.cast()) } {
                    spec = spec.address(IpNet::new(ip, entry.OnLinkPrefixLength));
                }
                u = entry.Next;
            }
            return Some(spec);
        }
        at = a.Next;
    }
    None
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

fn wide_str(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let len = (0..).take_while(|&i| unsafe { *p.add(i) } != 0).count();
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(p, len) })
}

/// The [`Adapter`] whose keys answer like the real one found: `Adapter::new`'s defaults the real
/// driver lacks removed, every keyword it has set to its value and maximum.
fn adapter_from(found: &Found) -> Adapter {
    let mut adapter = Adapter::new();
    if let Ok(version) = &found.driver_version {
        adapter = adapter.driver_version(version.clone());
    }
    for (keyword, read) in &found.keywords {
        adapter = match read {
            Ok((value, max)) => adapter.property(*keyword, value.clone(), *max),
            Err(_) => adapter.without_property(keyword),
        };
    }
    adapter
}

/// A sim with one interface mirroring the real adapter and `adapter` on it, holding the real
/// token's elevation.
fn sim_for(alias: &str, spec: NicSpec, adapter: Adapter) -> Sim {
    let privileges = if elevated() {
        Privileges::all()
    } else {
        Privileges::none()
    };
    Sim::builder()
        .nic(spec)
        .adapter(alias, adapter)
        .privileges(privileges)
        .build()
}

#[test]
#[ignore = "hardware: needs a wired adapter"]
fn hw_win_adapter_reads_match_the_model() {
    let alias = need!(hw::hw().win_adapter.clone(), "{NEEDS_ADAPTER}");
    let real = snare::real(|| probe(&alias));
    require!(
        real.device.is_ok(),
        "{alias} has no device node in the network class ({:?})",
        real.device
    );
    let spec = need!(
        snare::real(|| nic_spec(&alias)),
        "GetAdaptersAddresses does not list {alias}"
    );
    let sim = sim_for(&alias, spec, adapter_from(&real)).run(|| probe(&alias));
    eprintln!("{alias} (elevated {}): {real:#?}", elevated());
    assert_eq!(sim.device, real.device, "device node found");
    assert_eq!(sim.driver_version, real.driver_version, "DriverVersion");
    for ((keyword, r), (_, s)) in real.keywords.iter().zip(&sim.keywords) {
        assert_eq!(s, r, "{keyword}: value and Ndi\\Params max");
    }
    assert_eq!(
        sim.writable, real.writable,
        "SetupDiOpenDevRegKey(DIREG_DRV, KEY_SET_VALUE)"
    );
}

/// The real adapter's original value of `keyword`, written back (and the device restarted) when
/// dropped; the link is awaited.
struct Restore {
    alias: String,
    keyword: &'static str,
    value: String,
}

impl Drop for Restore {
    fn drop(&mut self) {
        snare::real(|| {
            let Ok(device) = Device::find(&self.alias) else {
                eprintln!("could not find {} to restore {}", self.alias, self.keyword);
                return;
            };
            let rc = device
                .key(KEY_READ | KEY_SET_VALUE)
                .map(|k| k.set_string(self.keyword, &self.value));
            let restart = device.restart();
            eprintln!(
                "restored {} {} = {}: {rc:?}, restart {restart:?}",
                self.alias, self.keyword, self.value
            );
            for _ in 0..600 {
                if if_row(&self.alias).is_ok_and(|r| r.OperStatus == IfOperStatusUp) {
                    break;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        });
    }
}

/// Writing a keyword and restarting the device: the write and the two Configuration Manager calls
/// succeed alike, the link is down right after the restart, and the value reads back.
#[test]
#[ignore = "hardware: needs a wired adapter, an elevated token and SNARE_HW_MUTATE=1"]
fn hw_win_adapter_write_and_restart_match() {
    let h = hw::hw();
    let alias = need!(h.win_adapter.clone(), "{NEEDS_ADAPTER}");
    require!(
        h.mutate,
        "changes {alias}'s advanced properties and restarts it (set SNARE_HW_MUTATE=1; restored after)"
    );
    require!(elevated(), "needs an elevated (administrator) token");
    let real_found = snare::real(|| probe(&alias));
    let (keyword, original) = need!(
        real_found
            .keywords
            .iter()
            .find(|(k, r)| *k == "*InterruptModeration" && r.is_ok())
            .or_else(|| real_found
                .keywords
                .iter()
                .find(|(k, r)| *k == "*FlowControl" && r.is_ok()))
            .and_then(|(k, r)| r.as_ref().ok().map(|(v, _)| (*k, v.clone()))),
        "{alias} has neither *InterruptModeration nor *FlowControl to toggle"
    );
    let spec = need!(
        snare::real(|| nic_spec(&alias)),
        "GetAdaptersAddresses does not list {alias}"
    );
    let changed = if original == "0" { "1" } else { "0" };
    let _restore = Restore {
        alias: alias.clone(),
        keyword,
        value: original.clone(),
    };
    let apply = || {
        let device = Device::find(&alias).unwrap();
        let set = device
            .key(KEY_READ | KEY_SET_VALUE)
            .map(|k| k.set_string(keyword, changed));
        let restart = device.restart();
        let down = if_row(&alias).map(|r| r.OperStatus == IfOperStatusUp);
        let read = device.key(KEY_READ).map(|k| k.string(keyword));
        (set, restart, down, read)
    };
    let real = snare::real(apply);
    let sim = sim_for(&alias, spec, adapter_from(&real_found)).run(apply);
    assert_eq!(
        sim, real,
        "{keyword} {original} -> {changed}: (write, (disable, enable), link up after, read back)"
    );
}
