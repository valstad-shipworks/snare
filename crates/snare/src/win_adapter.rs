//! Network adapters as Windows device nodes: the SetupAPI device list, the registry keys holding
//! each adapter's advanced properties, and the disable/enable restart that applies them.
//!
//! A program tunes a Windows adapter the way Device Manager and `Set-NetAdapterAdvancedProperty`
//! do: it enumerates the network device class with `SetupDiGetClassDevsW` /
//! `SetupDiEnumDeviceInfo`, opens each device's software key (`DIREG_DRV`, the driver key under
//! `Control\Class\{4d36e972-...}\NNNN`) with `SetupDiOpenDevRegKey`, picks the one whose
//! `NetCfgInstanceId` is the interface GUID IP Helper reports, writes standardized keywords
//! (`*ReceiveBuffers`, `*InterruptModeration`, ...) as `REG_SZ` values, reads their limits from
//! `Ndi\Params\<keyword>`, and restarts the device with `CM_Disable_DevNode` +
//! `CM_Enable_DevNode` so the driver re-reads them
//! ([Microsoft Learn: Standardized INF Keywords for Network Devices](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/standardized-inf-keywords-for-network-devices);
//! [Microsoft Learn: Specifying Configuration Parameters for the Advanced Properties Page](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/specifying-configuration-parameters-for-the-advanced-properties-page)).
//!
//! [`Adapters`] serves those calls for every non-loopback interface of the sim's topology. Each
//! adapter's two keys are an in-memory registry tree built on first use from the interface and
//! its [`Adapter`] description; whatever the code under test writes stays there and reads back.
//! A restart takes the interface's carrier down at `CM_Disable_DevNode` and schedules it back up
//! [`Adapter::restart_flap`] after `CM_Enable_DevNode` on the topology's deadline clock, so IP
//! Helper's `OperStatus`, the sockets and the virtual clock all see the same outage.
//!
//! Elevation is [`Privileges::root`](crate::Privileges::root): an elevated administrator token.
//! Without it, opening a key for writing, creating a subkey, and disabling or enabling a device
//! fail as they do for a standard user, whose token the class key's ACL and the Configuration
//! Manager refuse.
//!
//! All state sits behind one mutex, never held while the topology is changed: a restart's link
//! changes are made after it is released, since they wake waiters (the README's wake-after-unlock
//! rule).

use std::collections::{BTreeMap, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use snare_interpose::{DevCall, NetResult as HostResult};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CR_ACCESS_DENIED, CR_INVALID_DEVNODE, CR_SUCCESS, DICS_FLAG_CONFIGSPECIFIC, DICS_FLAG_GLOBAL,
    DIGCF_ALLCLASSES, DIGCF_DEVICEINTERFACE, DIREG_DEV, DIREG_DRV, GUID_DEVCLASS_NET,
    SP_DEVINFO_DATA,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_FLAGS, ERROR_INVALID_PARAMETER,
    ERROR_INVALID_USER_BUFFER, ERROR_KEY_DELETED, ERROR_MORE_DATA, ERROR_NO_MORE_ITEMS,
    ERROR_SUCCESS, GENERIC_ALL, GENERIC_READ, GENERIC_WRITE,
};
use windows_sys::Win32::System::Registry::{
    KEY_ALL_ACCESS, KEY_CREATE_LINK, KEY_CREATE_SUB_KEY, KEY_QUERY_VALUE, KEY_READ, KEY_SET_VALUE,
    KEY_WRITE, REG_BINARY, REG_CREATED_NEW_KEY, REG_DWORD, REG_OPENED_EXISTING_KEY, REG_SZ,
};

use crate::netif::NicSnapshot;
use crate::readiness::Deadline;
use crate::scope::SimShared;

/// One advanced property of an adapter: its current value, as the `REG_SZ` the driver key holds,
/// and the `max` its `Ndi\Params\<keyword>` description gives, if any. A property with a maximum
/// is described as `type` `int`, one without as `enum`, the two kinds the Advanced page shows
/// ([Microsoft Learn: Specifying Configuration Parameters for the Advanced Properties Page](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/specifying-configuration-parameters-for-the-advanced-properties-page)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedProperty {
    /// The value, e.g. `"256"`.
    pub value: String,
    /// The `max` of the keyword's `Ndi\Params` description.
    pub max: Option<u32>,
}

/// How a sim's Windows network adapter looks to SetupAPI and the registry: its driver version,
/// its advanced properties (by standardized keyword) and how long a restart drops its link.
/// Give one to [`SimBuilder::adapter`](crate::SimBuilder::adapter); an interface without one gets
/// [`Adapter::new`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Adapter {
    /// The driver key's `DriverVersion`.
    pub driver_version: String,
    /// The advanced properties by keyword (`*ReceiveBuffers`, `*FlowControl`, ...).
    pub properties: BTreeMap<String, AdvancedProperty>,
    /// How long the link stays down after `CM_Enable_DevNode` restarts the adapter.
    pub restart_flap: Duration,
}

impl Default for Adapter {
    fn default() -> Self {
        Adapter::new()
    }
}

impl Adapter {
    /// The default adapter, mirroring snare 1.x's `NicCaps` defaults (snare choices, not one real
    /// driver): `*ReceiveBuffers` and `*TransmitBuffers` 256 of at most 4096,
    /// `*InterruptModeration` 1 (enabled), `*FlowControl` 3 (Rx & Tx enabled), `*NumRssQueues` 4
    /// of at most 8, `*RSS` 1 (enabled) and `*SoftwareTimestamp` 0 (disabled), no EEE keyword,
    /// and a 2 s restart flap. The enumeration values are the standardized keywords'
    /// ([Microsoft Learn: Standardized INF Keywords for Flow Control](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/standardized-inf-keywords-for-flow-control);
    /// [Microsoft Learn: Standardized INF Keywords for Interrupt Moderation](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/standardized-inf-keywords-for-interrupt-moderation);
    /// [Microsoft Learn: Standardized INF Keywords for RSS](https://learn.microsoft.com/en-us/windows-hardware/drivers/network/standardized-inf-keywords-for-rss)).
    pub fn new() -> Self {
        Adapter {
            driver_version: env!("CARGO_PKG_VERSION").to_string(),
            properties: BTreeMap::new(),
            restart_flap: Duration::from_secs(2),
        }
        .property("*ReceiveBuffers", "256", Some(4096))
        .property("*TransmitBuffers", "256", Some(4096))
        .property("*InterruptModeration", "1", None)
        .property("*FlowControl", "3", None)
        .property("*NumRssQueues", "4", Some(8))
        .property("*RSS", "1", None)
        .property("*SoftwareTimestamp", "0", None)
    }

    /// Adds or replaces the property `keyword`.
    pub fn property(
        mut self,
        keyword: impl Into<String>,
        value: impl Into<String>,
        max: Option<u32>,
    ) -> Self {
        self.properties.insert(
            keyword.into(),
            AdvancedProperty {
                value: value.into(),
                max,
            },
        );
        self
    }

    /// Removes the property `keyword`, as for a driver that does not have it.
    pub fn without_property(mut self, keyword: &str) -> Self {
        self.properties.remove(keyword);
        self
    }

    /// Sets the driver version.
    pub fn driver_version(mut self, version: impl Into<String>) -> Self {
        self.driver_version = version.into();
        self
    }

    /// Sets how long a restart keeps the link down.
    pub fn restart_flap(mut self, flap: Duration) -> Self {
        self.restart_flap = flap;
        self
    }
}

/// Which of an adapter's two registry keys: the software key `SetupDiOpenDevRegKey` opens for
/// `DIREG_DRV`, or the hardware key's `Device Parameters` it opens for `DIREG_DEV`
/// ([Microsoft Learn: SetupDiOpenDevRegKey](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdapterKey {
    /// The driver (software) key, holding the advanced properties.
    Driver,
    /// The device (hardware) key's `Device Parameters`, holding e.g. the interrupt affinity
    /// policy.
    Device,
}

/// A registry value read back from an adapter's keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegValue {
    /// `REG_SZ`, without its terminator.
    Sz(String),
    /// `REG_DWORD`.
    Dword(u32),
    /// `REG_BINARY`.
    Binary(Vec<u8>),
    /// Any other type, with its raw data.
    Other {
        /// The `REG_*` type.
        ty: u32,
        /// The data as stored.
        data: Vec<u8>,
    },
}

/// The first device instance handle the sim mints; adapter `i` (by interface index) is this plus
/// `i`. A snare choice: real `DEVINST`s are small indices into the device tree (1 to 10 on the
/// test VM), so these never meet one.
const DEVINST_BASE: u32 = 0x736e_0000;

/// The first device information set or registry key handle the sim mints, counting up by four as
/// kernel handles do. A snare choice far above any real handle value, and below the predefined
/// keys (`HKEY_LOCAL_MACHINE` and friends sign-extend `0x8000000x`, `winreg.h`).
const HANDLE_BASE: u64 = 0x736e_6172_0000;

/// The standard rights `DELETE`, `WRITE_DAC` and `WRITE_OWNER` and the `MAXIMUM_ALLOWED` request
/// bit (`winnt.h`;
/// [Microsoft Learn: Standard Access Rights](https://learn.microsoft.com/en-us/windows/win32/secauthz/standard-access-rights),
/// [Microsoft Learn: ACCESS_MASK](https://learn.microsoft.com/en-us/windows/win32/secauthz/access-mask)).
const DELETE: u32 = 0x0001_0000;
/// `WRITE_DAC`; see [`DELETE`].
const WRITE_DAC: u32 = 0x0004_0000;
/// `WRITE_OWNER`; see [`DELETE`].
const WRITE_OWNER: u32 = 0x0008_0000;
/// `MAXIMUM_ALLOWED`; see [`DELETE`].
const MAXIMUM_ALLOWED: u32 = 0x0200_0000;

/// The access bits that change a key or its security (`winnt.h`), refused to a standard user on
/// an adapter's keys.
const WRITE_ACCESS: u32 = KEY_SET_VALUE
    | KEY_CREATE_SUB_KEY
    | KEY_CREATE_LINK
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// One stored value: its `REG_*` type and data.
#[derive(Clone)]
struct Value {
    ty: u32,
    data: Vec<u8>,
}

/// A registry tree: every key by its lower-cased path from the root (`""`), keys and value names
/// matching case-insensitively as the registry's do
/// ([Microsoft Learn: Structure of the Registry](https://learn.microsoft.com/en-us/windows/win32/sysinfo/structure-of-the-registry)).
#[derive(Default, Clone)]
struct Tree {
    keys: BTreeMap<String, BTreeMap<String, Value>>,
}

impl Tree {
    /// Creates `path` and every key above it; returns whether it was new.
    fn create(&mut self, path: &str) -> bool {
        let mut created = false;
        let mut at = String::new();
        self.keys.entry(String::new()).or_default();
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            if !at.is_empty() {
                at.push('\\');
            }
            at.push_str(&part.to_lowercase());
            if !self.keys.contains_key(&at) {
                self.keys.insert(at.clone(), BTreeMap::new());
                created = true;
            }
        }
        created
    }

    fn set(&mut self, path: &str, name: &str, ty: u32, data: Vec<u8>) {
        self.create(path);
        self.keys
            .get_mut(&path.to_lowercase())
            .unwrap()
            .insert(name.to_lowercase(), Value { ty, data });
    }

    fn set_sz(&mut self, path: &str, name: &str, value: &str) {
        self.set(path, name, REG_SZ, sz_bytes(value));
    }
}

/// `s` as a `REG_SZ`'s data: UTF-16LE with its terminator, as `RegSetValueExW` expects it
/// ([Microsoft Learn: RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)).
fn sz_bytes(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// `path` joined under `base`, lower-cased, without empty components.
fn join(base: &str, sub: &str) -> String {
    base.split('\\')
        .chain(sub.split('\\'))
        .filter(|p| !p.is_empty())
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join("\\")
}

/// One adapter's device node.
struct Device {
    /// The interface it is.
    nic: String,
    /// The software key.
    drv: Tree,
    /// The hardware key's `Device Parameters`.
    dev: Tree,
    flap: Duration,
    disabled: bool,
    baseline: Option<bool>,
    restore: Option<Deadline>,
    generation: Arc<Mutex<u64>>,
    restarts: u32,
}

impl Device {
    /// The device node of `nic` described by `adapter`: `NetCfgInstanceId` is the interface GUID
    /// IP Helper reports, upper-case and braced as the real key holds it (measured on the test VM),
    /// `DriverDesc` its description, and each property a `REG_SZ` with an `Ndi\Params\<keyword>`
    /// key carrying `ParamDesc`, `type`, `default` and any `max`, the names drivers' INFs use
    /// (measured on the test VM's adapter).
    fn new(nic: &NicSnapshot, adapter: &Adapter) -> Self {
        let mut drv = Tree::default();
        drv.create("");
        drv.set_sz(
            "",
            "NetCfgInstanceId",
            &crate::iphlp::guid_string(&crate::iphlp::guid(nic)),
        );
        drv.set_sz("", "DriverDesc", &crate::iphlp::description(nic));
        drv.set_sz("", "DriverVersion", &adapter.driver_version);
        for (keyword, p) in &adapter.properties {
            drv.set_sz("", keyword, &p.value);
            let params = format!("Ndi\\Params\\{keyword}");
            drv.set_sz(&params, "ParamDesc", keyword);
            drv.set_sz(
                &params,
                "type",
                if p.max.is_some() { "int" } else { "enum" },
            );
            drv.set_sz(&params, "default", &p.value);
            if let Some(max) = p.max {
                drv.set_sz(&params, "max", &max.to_string());
            }
        }
        let mut dev = Tree::default();
        dev.create("");
        Device {
            nic: nic.spec.name.clone(),
            drv,
            dev,
            flap: adapter.restart_flap,
            disabled: false,
            baseline: None,
            restore: None,
            generation: Arc::new(Mutex::new(0)),
            restarts: 0,
        }
    }

    fn tree(&self, key: AdapterKey) -> &Tree {
        match key {
            AdapterKey::Driver => &self.drv,
            AdapterKey::Device => &self.dev,
        }
    }

    fn tree_mut(&mut self, key: AdapterKey) -> &mut Tree {
        match key {
            AdapterKey::Driver => &mut self.drv,
            AdapterKey::Device => &mut self.dev,
        }
    }
}

/// An open registry key handle.
struct OpenKey {
    devinst: u32,
    which: AdapterKey,
    /// Lower-cased path from the key's root.
    path: String,
    /// The access granted.
    access: u32,
}

impl OpenKey {
    /// The handle's device, key, path and granted access, copied out of the state.
    fn parts(&self) -> (u32, AdapterKey, String, u32) {
        (self.devinst, self.which, self.path.clone(), self.access)
    }
}

#[derive(Default)]
struct State {
    /// The test's descriptions by interface name.
    configured: HashMap<String, Adapter>,
    /// Device nodes built so far, by `DEVINST`.
    devices: BTreeMap<u32, Device>,
    /// Open device information sets and their devices, in enumeration order.
    sets: HashMap<u64, Vec<u32>>,
    keys: HashMap<u64, OpenKey>,
    /// Handles minted so far.
    minted: u64,
}

impl State {
    fn mint(&mut self) -> u64 {
        self.minted += 1;
        HANDLE_BASE + 4 * self.minted
    }

    /// The device node of `nic`, built on first use.
    fn device(&mut self, nic: &NicSnapshot) -> u32 {
        let devinst = DEVINST_BASE + nic.index;
        if !self.devices.contains_key(&devinst) {
            let adapter = self
                .configured
                .get(&nic.spec.name)
                .cloned()
                .unwrap_or_default();
            self.devices.insert(devinst, Device::new(nic, &adapter));
        }
        devinst
    }
}

/// What a `CM_*` call leaves to do on the topology once the state lock is released.
struct LinkChange {
    nic: String,
    generation: Arc<Mutex<u64>>,
    epoch: u64,
    restore: Option<Deadline>,
}

/// The sim's adapters; see the module docs.
#[derive(Default)]
pub(crate) struct Adapters {
    state: Mutex<State>,
}

/// The GUID's 16 bytes as it lies in memory (`guiddef.h`: `Data1` to `Data3` little-endian on
/// Windows' little-endian targets, then `Data4`).
fn guid_bytes(g: &windows_sys::core::GUID) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..4].copy_from_slice(&g.data1.to_le_bytes());
    b[4..6].copy_from_slice(&g.data2.to_le_bytes());
    b[6..8].copy_from_slice(&g.data3.to_le_bytes());
    b[8..].copy_from_slice(&g.data4);
    b
}

/// The access a request is granted, mapping the generic rights to the key rights (`KEY_READ`,
/// `KEY_WRITE`, `KEY_ALL_ACCESS`,
/// [Microsoft Learn: Registry Key Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-key-security-and-access-rights)),
/// or `ERROR_ACCESS_DENIED` for a write a standard user asks for. `MAXIMUM_ALLOWED` gets what the
/// token may have: everything elevated, reading otherwise.
fn grant(access: u32, elevated: bool) -> Result<u32, u32> {
    if access & WRITE_ACCESS != 0 && !elevated {
        return Err(ERROR_ACCESS_DENIED);
    }
    let mut granted = access & KEY_ALL_ACCESS;
    if access & GENERIC_READ != 0 {
        granted |= KEY_READ;
    }
    if access & GENERIC_WRITE != 0 {
        granted |= KEY_WRITE;
    }
    if access & GENERIC_ALL != 0 {
        granted |= KEY_ALL_ACCESS;
    }
    if access & MAXIMUM_ALLOWED != 0 {
        granted |= if elevated { KEY_ALL_ACCESS } else { KEY_READ };
    }
    Ok(granted)
}

/// The `SP_DEVINFO_DATA` at `data` is the caller's to fill or read only if its `cbSize` is the
/// structure's size; otherwise SetupAPI fails with `ERROR_INVALID_USER_BUFFER` (measured on the
/// test VM with `cbSize` 3; `nic_adapter_props_win`'s `setupapi_codes_os_truth` pins it). A null
/// pointer fails the same way, a snare choice.
///
/// # Safety
/// `data` is null or points at an `SP_DEVINFO_DATA`.
unsafe fn devinfo<'a>(data: *const u8) -> Result<&'a SP_DEVINFO_DATA, u32> {
    // SAFETY: as the caller guarantees; read unaligned since the caller's struct may be packed.
    let d = unsafe { data.cast::<SP_DEVINFO_DATA>().as_ref() }.ok_or(ERROR_INVALID_USER_BUFFER)?;
    if d.cbSize as usize != size_of::<SP_DEVINFO_DATA>() {
        return Err(ERROR_INVALID_USER_BUFFER);
    }
    Ok(d)
}

impl Adapters {
    /// Describes the adapter of interface `nic` from now on, rebuilding its keys (and dropping
    /// what was written to them) the next time they are used.
    pub(crate) fn configure(&self, shared: &SimShared, nic: &str, adapter: Adapter) {
        let cancelled = {
            let mut state = self.state.lock().unwrap();
            let mut cancelled = Vec::new();
            state.devices.retain(|_, device| {
                if device.nic != nic {
                    return true;
                }
                let mut generation = device.generation.lock().unwrap_or_else(|e| e.into_inner());
                *generation = generation.wrapping_add(1);
                cancelled.push(device.generation.clone());
                false
            });
            state.configured.insert(nic.to_string(), adapter);
            cancelled
        };
        for generation in cancelled {
            shared.cancel_adapter_link(nic, &generation);
        }
    }

    /// The value `name` under `path` of `nic`'s `key`, as the code under test would read it.
    pub(crate) fn value(
        &self,
        shared: &SimShared,
        nic: &str,
        key: AdapterKey,
        path: &str,
        name: &str,
    ) -> Option<RegValue> {
        let snapshot = shared.nic(nic).filter(|n| !n.loopback)?;
        let mut state = self.state.lock().unwrap();
        let devinst = state.device(&snapshot);
        let value = state.devices[&devinst]
            .tree(key)
            .keys
            .get(&join("", path))?
            .get(&name.to_lowercase())?
            .clone();
        let u16s = || {
            let units: Vec<u16> = value
                .data
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .collect();
            let end = units.iter().position(|&u| u == 0).unwrap_or(units.len());
            String::from_utf16_lossy(&units[..end])
        };
        Some(match value.ty {
            REG_SZ => RegValue::Sz(u16s()),
            REG_DWORD if value.data.len() == 4 => {
                RegValue::Dword(u32::from_le_bytes(value.data[..4].try_into().unwrap()))
            }
            REG_BINARY => RegValue::Binary(value.data),
            ty => RegValue::Other {
                ty,
                data: value.data,
            },
        })
    }

    /// How many times `nic`'s adapter has been restarted (enabled after a disable).
    pub(crate) fn restarts(&self, nic: &str) -> u32 {
        let state = self.state.lock().unwrap();
        state
            .devices
            .values()
            .find(|d| d.nic == nic)
            .map_or(0, |d| d.restarts)
    }

    /// Serves one SetupAPI, Configuration Manager or registry call; `None` for a handle, device
    /// or class the sim does not own. Runs under passthrough (the host plane's dispatch).
    ///
    /// # Safety
    /// The pointers in `call` are the caller's, valid as the C function documents them.
    pub(crate) unsafe fn call(&self, shared: &SimShared, call: DevCall<'_>) -> Option<HostResult> {
        let elevated = shared.sys.privileges().root;
        match call {
            DevCall::GetClassDevs {
                class,
                enumerator,
                flags,
            } => {
                if class != Some(&guid_bytes(&GUID_DEVCLASS_NET))
                    || enumerator.is_some()
                    || flags & (DIGCF_ALLCLASSES | DIGCF_DEVICEINTERFACE) != 0
                {
                    return None;
                }
                let mut nics: Vec<NicSnapshot> =
                    shared.nics().into_iter().filter(|n| !n.loopback).collect();
                nics.sort_by_key(|n| n.index);
                let mut state = self.state.lock().unwrap();
                let devices = nics.iter().map(|n| state.device(n)).collect();
                let set = state.mint();
                state.sets.insert(set, devices);
                Some(HostResult::Ok(set as i64))
            }
            DevCall::EnumDeviceInfo { set, index, data } => {
                let state = self.state.lock().unwrap();
                let devices = state.sets.get(&set)?;
                // SAFETY: the caller's SP_DEVINFO_DATA, as SetupDiEnumDeviceInfo requires.
                if let Err(e) = unsafe { devinfo(data) } {
                    return Some(HostResult::Err(e as i32));
                }
                let Some(&devinst) = devices.get(index as usize) else {
                    return Some(HostResult::Err(ERROR_NO_MORE_ITEMS as i32));
                };
                let out = SP_DEVINFO_DATA {
                    cbSize: size_of::<SP_DEVINFO_DATA>() as u32,
                    ClassGuid: GUID_DEVCLASS_NET,
                    DevInst: devinst,
                    Reserved: 0,
                };
                // SAFETY: checked above to be a writable SP_DEVINFO_DATA.
                unsafe { data.cast::<SP_DEVINFO_DATA>().write_unaligned(out) };
                Some(HostResult::Ok(1))
            }
            DevCall::DestroyDeviceInfoList { set } => {
                let mut state = self.state.lock().unwrap();
                state.sets.remove(&set)?;
                Some(HostResult::Ok(1))
            }
            DevCall::OpenDevRegKey {
                set,
                data,
                scope,
                key_type,
                access,
                ..
            } => {
                let mut state = self.state.lock().unwrap();
                let devices = state.sets.get(&set)?;
                // SAFETY: the caller's SP_DEVINFO_DATA, as SetupDiOpenDevRegKey requires.
                let devinst = match unsafe { devinfo(data) } {
                    Ok(d) => d.DevInst,
                    Err(e) => return Some(HostResult::Err(e as i32)),
                };
                if !devices.contains(&devinst) {
                    return Some(HostResult::Err(ERROR_INVALID_PARAMETER as i32));
                }
                // KeyType must be DIREG_DEV or DIREG_DRV (measured: 7 fails with
                // ERROR_INVALID_FLAGS on the test VM); Scope DICS_FLAG_GLOBAL or
                // DICS_FLAG_CONFIGSPECIFIC (the page's two values; refusing others the same way is
                // a snare choice). Both scopes open the same key here.
                let which = match key_type {
                    DIREG_DRV => AdapterKey::Driver,
                    DIREG_DEV => AdapterKey::Device,
                    _ => return Some(HostResult::Err(ERROR_INVALID_FLAGS as i32)),
                };
                if scope != DICS_FLAG_GLOBAL && scope != DICS_FLAG_CONFIGSPECIFIC {
                    return Some(HostResult::Err(ERROR_INVALID_FLAGS as i32));
                }
                let access = match grant(access, elevated) {
                    Ok(a) => a,
                    Err(e) => return Some(HostResult::Err(e as i32)),
                };
                let key = state.mint();
                state.keys.insert(
                    key,
                    OpenKey {
                        devinst,
                        which,
                        path: String::new(),
                        access,
                    },
                );
                Some(HostResult::Ok(key as i64))
            }
            DevCall::DisableDevNode { devinst, .. } | DevCall::EnableDevNode { devinst, .. } => {
                let enable = matches!(call, DevCall::EnableDevNode { .. });
                let change = {
                    let mut state = self.state.lock().unwrap();
                    let device = state.devices.get_mut(&devinst)?;
                    if !elevated {
                        return Some(HostResult::Ok(CR_ACCESS_DENIED as i64));
                    }
                    let Some(nic) = shared.nic(&device.nic) else {
                        return Some(HostResult::Ok(CR_INVALID_DEVNODE as i64));
                    };
                    if device.restore.is_some_and(|at| at.passed()) {
                        device.restore = None;
                        device.baseline = None;
                    }
                    if enable == !device.disabled {
                        None
                    } else {
                        let mut generation =
                            device.generation.lock().unwrap_or_else(|e| e.into_inner());
                        *generation = generation.wrapping_add(1);
                        if enable {
                            device.disabled = false;
                            device.restarts += 1;
                            device.restore = device
                                .baseline
                                .filter(|carrier| *carrier)
                                .map(|_| Deadline::after(device.flap));
                            if device.restore.is_none() {
                                device.baseline = None;
                            }
                        } else {
                            device.baseline.get_or_insert(nic.spec.carrier);
                            device.disabled = true;
                            device.restore = None;
                        }
                        Some(LinkChange {
                            nic: device.nic.clone(),
                            generation: device.generation.clone(),
                            epoch: *generation,
                            restore: device.restore,
                        })
                    }
                };
                if let Some(change) = change {
                    let _ = shared.adapter_link(
                        &change.nic,
                        &change.generation,
                        change.epoch,
                        change.restore,
                    );
                }
                Some(HostResult::Ok(CR_SUCCESS as i64))
            }
            DevCall::OpenKey {
                key,
                subkey,
                access,
                result,
            } => {
                let mut state = self.state.lock().unwrap();
                let (devinst, which, base, _) = state.keys.get(&key)?.parts();
                let status = (|| {
                    if result.is_null() {
                        return Err(ERROR_INVALID_PARAMETER);
                    }
                    let path = join(&base, &String::from_utf16_lossy(subkey.unwrap_or(&[])));
                    let device = state.devices.get(&devinst).ok_or(ERROR_KEY_DELETED)?;
                    if !device.tree(which).keys.contains_key(&path) {
                        return Err(ERROR_FILE_NOT_FOUND);
                    }
                    let access = grant(access, elevated)?;
                    let handle = state.mint();
                    state.keys.insert(
                        handle,
                        OpenKey {
                            devinst,
                            which,
                            path,
                            access,
                        },
                    );
                    // SAFETY: checked non-null; the caller's PHKEY.
                    unsafe { result.write_unaligned(handle) };
                    Ok(())
                })();
                Some(HostResult::Ok(status.err().unwrap_or(ERROR_SUCCESS) as i64))
            }
            DevCall::CreateKey {
                key,
                subkey,
                access,
                result,
                disposition,
            } => {
                let mut state = self.state.lock().unwrap();
                let (devinst, which, base, _) = state.keys.get(&key)?.parts();
                let status = (|| {
                    if result.is_null() {
                        return Err(ERROR_INVALID_PARAMETER);
                    }
                    // A standard user may not create under an adapter's keys; the parent
                    // handle's own access is not what decides (measured on the test VM:
                    // RegCreateKeyExW under a key opened KEY_READ succeeds for an administrator).
                    if !elevated {
                        return Err(ERROR_ACCESS_DENIED);
                    }
                    let access = grant(access, elevated)?;
                    let path = join(&base, &String::from_utf16_lossy(subkey.unwrap_or(&[])));
                    let device = state.devices.get_mut(&devinst).ok_or(ERROR_KEY_DELETED)?;
                    let created = device.tree_mut(which).create(&path);
                    let handle = state.mint();
                    state.keys.insert(
                        handle,
                        OpenKey {
                            devinst,
                            which,
                            path,
                            access,
                        },
                    );
                    // SAFETY: checked non-null; the caller's PHKEY and optional disposition.
                    unsafe {
                        result.write_unaligned(handle);
                        if !disposition.is_null() {
                            disposition.write_unaligned(if created {
                                REG_CREATED_NEW_KEY
                            } else {
                                REG_OPENED_EXISTING_KEY
                            });
                        }
                    }
                    Ok(())
                })();
                Some(HostResult::Ok(status.err().unwrap_or(ERROR_SUCCESS) as i64))
            }
            DevCall::QueryValue {
                key,
                name,
                ty,
                data,
                len,
            } => {
                let state = self.state.lock().unwrap();
                let open = state.keys.get(&key)?;
                // SAFETY: the caller's out-pointers, as RegQueryValueExW documents them.
                let status = unsafe { query(&state, open, name, ty, data, len) };
                Some(HostResult::Ok(status.err().unwrap_or(ERROR_SUCCESS) as i64))
            }
            DevCall::SetValue {
                key,
                name,
                ty,
                data,
                len,
            } => {
                let mut state = self.state.lock().unwrap();
                let (devinst, which, path, granted) = state.keys.get(&key)?.parts();
                let status = (|| {
                    // Measured on the test VM: RegSetValueExW on a key opened KEY_READ fails with
                    // ERROR_ACCESS_DENIED even for an administrator.
                    if granted & KEY_SET_VALUE == 0 {
                        return Err(ERROR_ACCESS_DENIED);
                    }
                    if data.is_null() && len != 0 {
                        return Err(ERROR_INVALID_PARAMETER);
                    }
                    let bytes = if len == 0 {
                        Vec::new()
                    } else {
                        // SAFETY: the caller's `len` readable bytes.
                        unsafe { std::slice::from_raw_parts(data, len as usize) }.to_vec()
                    };
                    let name = String::from_utf16_lossy(name.unwrap_or(&[]));
                    let device = state.devices.get_mut(&devinst).ok_or(ERROR_KEY_DELETED)?;
                    device.tree_mut(which).set(&path, &name, ty, bytes);
                    Ok(())
                })();
                Some(HostResult::Ok(status.err().unwrap_or(ERROR_SUCCESS) as i64))
            }
            DevCall::DeleteValue { key, name } => {
                let mut state = self.state.lock().unwrap();
                let (devinst, which, path, granted) = state.keys.get(&key)?.parts();
                let status = (|| {
                    if granted & KEY_SET_VALUE == 0 {
                        return Err(ERROR_ACCESS_DENIED);
                    }
                    let name = String::from_utf16_lossy(name.unwrap_or(&[])).to_lowercase();
                    let device = state.devices.get_mut(&devinst).ok_or(ERROR_KEY_DELETED)?;
                    let values = device
                        .tree_mut(which)
                        .keys
                        .get_mut(&path)
                        .ok_or(ERROR_KEY_DELETED)?;
                    values.remove(&name).map(drop).ok_or(ERROR_FILE_NOT_FOUND)
                })();
                Some(HostResult::Ok(status.err().unwrap_or(ERROR_SUCCESS) as i64))
            }
            DevCall::CloseKey { key } => {
                self.state.lock().unwrap().keys.remove(&key)?;
                Some(HostResult::Ok(ERROR_SUCCESS as i64))
            }
        }
    }
}

/// `RegQueryValueExW` on a sim key. A missing value is `ERROR_FILE_NOT_FOUND` with `*len`
/// untouched; a null `data` reports the size alone; a buffer without a `len` is
/// `ERROR_INVALID_PARAMETER`; a short buffer is `ERROR_MORE_DATA` with the size and type stored
/// (all measured on the test VM; `nic_adapter_props_win`'s `registry_codes_os_truth` pins them)
/// ([Microsoft Learn: RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw)).
/// A handle without `KEY_QUERY_VALUE` is `ERROR_ACCESS_DENIED`.
///
/// # Safety
/// `ty`, `data` and `len` are null or the caller's, as the function documents them.
unsafe fn query(
    state: &State,
    open: &OpenKey,
    name: Option<&[u16]>,
    ty: *mut u32,
    data: *mut u8,
    len: *mut u32,
) -> Result<(), u32> {
    if open.access & KEY_QUERY_VALUE == 0 {
        return Err(ERROR_ACCESS_DENIED);
    }
    if !data.is_null() && len.is_null() {
        return Err(ERROR_INVALID_PARAMETER);
    }
    let device = state.devices.get(&open.devinst).ok_or(ERROR_KEY_DELETED)?;
    let name = String::from_utf16_lossy(name.unwrap_or(&[])).to_lowercase();
    let value = device
        .tree(open.which)
        .keys
        .get(&open.path)
        .ok_or(ERROR_KEY_DELETED)?
        .get(&name)
        .ok_or(ERROR_FILE_NOT_FOUND)?;
    let size = value.data.len() as u32;
    // SAFETY (block): each pointer is written only when non-null, as the caller's out-parameter.
    unsafe {
        if !ty.is_null() {
            ty.write_unaligned(value.ty);
        }
        if len.is_null() {
            return Ok(());
        }
        let room = len.read_unaligned();
        len.write_unaligned(size);
        if data.is_null() {
            return Ok(());
        }
        if room < size {
            return Err(ERROR_MORE_DATA);
        }
        std::ptr::copy_nonoverlapping(value.data.as_ptr(), data, value.data.len());
    }
    Ok(())
}
