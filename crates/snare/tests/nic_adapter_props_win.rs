#![cfg(windows)]

//! Windows adapter tuning through SetupAPI, the registry and the Configuration Manager, made the
//! way fast-talker's `nic/windows.rs` makes it: find the device node whose driver key's
//! `NetCfgInstanceId` is the interface GUID, read a standardized keyword and its
//! `Ndi\Params\<keyword>\max`, write it, restart the device (link down for the restart flap), and
//! the working-set bounds of `rt/windows.rs`'s `reserve_working_set`.

use std::mem::{size_of, zeroed};
use std::ptr;
use std::time::{Duration, Instant};

use snare::{Adapter, AdapterKey, IpNet, NicSpec, Privileges, RegValue, Sim};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation::{
    CM_DISABLE_UI_NOT_OK, CM_Disable_DevNode, CM_Enable_DevNode, CR_ACCESS_DENIED, CR_SUCCESS,
    DICS_FLAG_GLOBAL, DIGCF_PRESENT, DIREG_DEV, DIREG_DRV, GUID_DEVCLASS_NET, HDEVINFO,
    SP_DEVINFO_DATA, SetupDiDestroyDeviceInfoList, SetupDiEnumDeviceInfo, SetupDiGetClassDevsW,
    SetupDiOpenDevRegKey,
};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_PARAMETER, ERROR_NO_SYSTEM_RESOURCES,
    ERROR_PRIVILEGE_NOT_HELD, ERROR_SUCCESS, GetLastError, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    ConvertInterfaceAliasToLuid, GetIfEntry2, MIB_IF_ROW2,
};
use windows_sys::Win32::NetworkManagement::Ndis::{IfOperStatusDown, IfOperStatusUp, NET_LUID_LH};
use windows_sys::Win32::System::Memory::{
    GetProcessWorkingSetSizeEx, QUOTA_LIMITS_HARDWS_MAX_DISABLE, QUOTA_LIMITS_HARDWS_MIN_ENABLE,
    SetProcessWorkingSetSizeEx,
};
use windows_sys::Win32::System::Registry::{
    HKEY, HKEY_CURRENT_USER, KEY_CREATE_SUB_KEY, KEY_READ, KEY_SET_VALUE, REG_BINARY,
    REG_CREATED_NEW_KEY, REG_DWORD, REG_OPENED_EXISTING_KEY, REG_OPTION_VOLATILE, REG_SZ,
    RegCloseKey, RegCreateKeyExW, RegDeleteKeyW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
    RegSetValueExW,
};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::core::GUID;

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

fn sim_builder() -> snare::SimBuilder {
    Sim::builder()
        .nic(
            NicSpec::new("eth0")
                .index(4)
                .address("10.0.0.1/24".parse::<IpNet>().unwrap()),
        )
        .nic(
            NicSpec::new("eth1")
                .index(5)
                .address("10.1.0.1/24".parse::<IpNet>().unwrap()),
        )
}

fn if_row(alias: &str) -> MIB_IF_ROW2 {
    let mut luid: NET_LUID_LH = unsafe { zeroed() };
    assert_eq!(
        unsafe { ConvertInterfaceAliasToLuid(wide(alias).as_ptr(), &mut luid) },
        ERROR_SUCCESS
    );
    let mut row: MIB_IF_ROW2 = unsafe { zeroed() };
    row.InterfaceLuid = luid;
    assert_eq!(unsafe { GetIfEntry2(&mut row) }, ERROR_SUCCESS);
    row
}

/// fast-talker's `Device`: a device information set and one device in it.
struct Device {
    set: HDEVINFO,
    data: SP_DEVINFO_DATA,
}

impl Device {
    fn find(alias: &str) -> Device {
        let want = guid_string(&if_row(alias).InterfaceGuid);
        let set = unsafe {
            SetupDiGetClassDevsW(
                &GUID_DEVCLASS_NET,
                ptr::null(),
                ptr::null_mut(),
                DIGCF_PRESENT,
            )
        };
        assert_ne!(set, INVALID_HANDLE_VALUE as HDEVINFO);
        let mut device = Device {
            set,
            data: unsafe { zeroed() },
        };
        for i in 0.. {
            device.data = unsafe { zeroed() };
            device.data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            if unsafe { SetupDiEnumDeviceInfo(set, i, &mut device.data) } == 0 {
                assert_eq!(unsafe { GetLastError() }, 259, "ERROR_NO_MORE_ITEMS");
                break;
            }
            let id = device
                .key(DIREG_DRV, KEY_READ)
                .and_then(|k| k.string("NetCfgInstanceId"));
            if id.is_ok_and(|id| id.eq_ignore_ascii_case(&want)) {
                return device;
            }
        }
        panic!("no device node for {alias}");
    }

    fn key(&self, which: u32, access: u32) -> Result<Key, u32> {
        let h = unsafe {
            SetupDiOpenDevRegKey(self.set, &self.data, DICS_FLAG_GLOBAL, 0, which, access)
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

/// fast-talker's `Key`.
struct Key(HKEY);

fn check(e: u32) -> Result<(), u32> {
    if e == ERROR_SUCCESS { Ok(()) } else { Err(e) }
}

impl Key {
    fn string(&self, name: &str) -> Result<String, u32> {
        let name = wide(name);
        let mut buf = [0u16; 256];
        let mut len = size_of::<[u16; 256]>() as u32;
        let mut typ = 0;
        check(unsafe {
            RegQueryValueExW(
                self.0,
                name.as_ptr(),
                ptr::null(),
                &mut typ,
                buf.as_mut_ptr().cast(),
                &mut len,
            )
        })?;
        assert_eq!(typ, REG_SZ);
        let units = &buf[..len as usize / 2];
        let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
        Ok(String::from_utf16_lossy(&units[..end]))
    }

    fn set_string(&self, name: &str, value: &str) -> Result<(), u32> {
        let value = wide(value);
        self.set_value(name, REG_SZ, unsafe {
            std::slice::from_raw_parts(value.as_ptr().cast(), value.len() * 2)
        })
    }

    fn set_value(&self, name: &str, typ: u32, data: &[u8]) -> Result<(), u32> {
        let name = wide(name);
        check(unsafe {
            RegSetValueExW(
                self.0,
                name.as_ptr(),
                0,
                typ,
                data.as_ptr(),
                data.len() as u32,
            )
        })
    }

    fn subkey(&self, path: &str) -> Result<Key, u32> {
        let path = wide(path);
        let mut h: HKEY = ptr::null_mut();
        check(unsafe { RegOpenKeyExW(self.0, path.as_ptr(), 0, KEY_READ, &mut h) })?;
        Ok(Key(h))
    }

    fn create_subkey(&self, path: &str) -> Result<(Key, u32), u32> {
        let path = wide(path);
        let mut h: HKEY = ptr::null_mut();
        let mut disposition = 0;
        check(unsafe {
            RegCreateKeyExW(
                self.0,
                path.as_ptr(),
                0,
                ptr::null(),
                0,
                KEY_READ | KEY_SET_VALUE,
                ptr::null(),
                &mut h,
                &mut disposition,
            )
        })?;
        Ok((Key(h), disposition))
    }

    /// fast-talker's `keyword`: the value and the `Ndi\Params` maximum (0 when none).
    fn keyword(&self, name: &str) -> Result<(u32, u32), u32> {
        let value = self.string(name)?;
        let max = self
            .subkey(&format!(r"Ndi\Params\{name}"))
            .and_then(|k| k.string("max"))
            .ok()
            .and_then(|m| m.trim().parse().ok())
            .unwrap_or(0);
        Ok((value.trim().parse().unwrap(), max))
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { RegCloseKey(self.0) };
    }
}

/// fast-talker's `apply`: write the changed keyword, then restart.
fn apply(alias: &str, name: &str, value: u32) {
    let device = Device::find(alias);
    let key = device.key(DIREG_DRV, KEY_READ | KEY_SET_VALUE).unwrap();
    key.set_string(name, &value.to_string()).unwrap();
    assert_eq!(device.restart(), (CR_SUCCESS, CR_SUCCESS));
}

#[test]
fn finds_the_adapter_and_reads_its_keywords() {
    let sim = sim_builder()
        .adapter(
            "eth1",
            Adapter::new()
                .driver_version("12.19.2.45")
                .property("*ReceiveBuffers", "512", Some(2048))
                .property("*EEE", "1", None),
        )
        .build();
    sim.run(|| {
        let eth0 = Device::find("eth0");
        let eth1 = Device::find("eth1");
        assert_ne!(eth0.data.DevInst, eth1.data.DevInst);
        let k0 = eth0.key(DIREG_DRV, KEY_READ).unwrap();
        assert_eq!(k0.keyword("*ReceiveBuffers"), Ok((256, 4096)));
        assert_eq!(k0.keyword("*FlowControl"), Ok((3, 0)));
        assert_eq!(k0.keyword("*EEE"), Err(ERROR_FILE_NOT_FOUND));
        let k1 = eth1.key(DIREG_DRV, KEY_READ).unwrap();
        assert_eq!(k1.keyword("*ReceiveBuffers"), Ok((512, 2048)));
        assert_eq!(k1.keyword("*EEE"), Ok((1, 0)));
        assert_eq!(k1.string("DriverVersion").as_deref(), Ok("12.19.2.45"));
        assert_eq!(k1.subkey(r"Ndi\NoSuch").err(), Some(ERROR_FILE_NOT_FOUND));
        assert_eq!(
            k1.subkey(r"ndi\PARAMS\*receivebuffers")
                .and_then(|k| k.string("TYPE"))
                .as_deref(),
            Ok("int"),
            "keys and value names match case-insensitively"
        );
    });
}

/// The ring change applies with a restart that drops the link for the 2 s flap, on the virtual
/// clock: down at once, still down just before the flap ends, up just after.
fn restart_flaps_the_link() {
    let start = Instant::now();
    apply("eth0", "*ReceiveBuffers", 1024);
    assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
    assert_eq!(
        if_row("eth1").OperStatus,
        IfOperStatusUp,
        "only eth0 restarted"
    );
    std::thread::sleep(Duration::from_millis(1990));
    assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
    std::thread::sleep(Duration::from_millis(20));
    assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp);
    let elapsed = start.elapsed();
    assert!(elapsed >= Duration::from_millis(2010), "{elapsed:?}");
    let device = Device::find("eth0");
    let key = device.key(DIREG_DRV, KEY_READ).unwrap();
    assert_eq!(key.keyword("*ReceiveBuffers"), Ok((1024, 4096)));
}

#[test]
fn restart_flaps_the_link_on_the_virtual_clock() {
    let sim = sim_builder().build();
    let real = Instant::now();
    sim.run(restart_flaps_the_link);
    assert!(
        real.elapsed() < Duration::from_secs(2),
        "virtual, not real, time"
    );
    assert_eq!(
        sim.adapter_property("eth0", "*ReceiveBuffers").as_deref(),
        Some("1024")
    );
    assert_eq!(sim.adapter_restarts("eth0"), 1);
    assert_eq!(sim.adapter_restarts("eth1"), 0);
}

#[test]
fn restart_flaps_the_link_deterministically() {
    let sim = sim_builder().deterministic().build();
    sim.run(restart_flaps_the_link);
    assert_eq!(sim.adapter_restarts("eth0"), 1);
}

#[test]
fn restart_flap_is_configurable() {
    let sim = sim_builder()
        .adapter(
            "eth0",
            Adapter::new().restart_flap(Duration::from_millis(500)),
        )
        .build();
    sim.run(|| {
        apply("eth0", "*InterruptModeration", 0);
        assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
        std::thread::sleep(Duration::from_millis(510));
        assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp);
    });
    sim.set_adapter("eth0", Adapter::new().restart_flap(Duration::ZERO));
    sim.run(|| {
        apply("eth0", "*InterruptModeration", 0);
        assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp, "no flap");
    });
    assert_eq!(
        sim.adapter_restarts("eth0"),
        1,
        "set_adapter starts the node afresh"
    );
}

#[test]
fn a_restart_keeps_a_link_without_carrier_down() {
    let sim = sim_builder().build();
    sim.set_link("eth0", false).unwrap();
    sim.run(|| {
        apply("eth0", "*RSS", 0);
        std::thread::sleep(Duration::from_secs(3));
        assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
    });
}

#[test]
fn disabling_during_a_restart_cancels_carrier_restoration() {
    for deterministic in [false, true] {
        let builder = sim_builder();
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let device = Device::find("eth0");
            assert_eq!(device.restart(), (CR_SUCCESS, CR_SUCCESS));
            std::thread::sleep(Duration::from_secs(1));
            assert_eq!(
                unsafe { CM_Disable_DevNode(device.data.DevInst, CM_DISABLE_UI_NOT_OK) },
                CR_SUCCESS
            );
            std::thread::sleep(Duration::from_secs(2));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
            assert_eq!(if_row("eth1").OperStatus, IfOperStatusUp);
            assert_eq!(
                unsafe { CM_Enable_DevNode(device.data.DevInst, 0) },
                CR_SUCCESS
            );
            std::thread::sleep(Duration::from_millis(1990));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
            std::thread::sleep(Duration::from_millis(20));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp);
        });
        assert_eq!(sim.adapter_restarts("eth0"), 2);
    }
}

#[test]
fn overlapping_restarts_use_the_latest_enable_deadline() {
    for deterministic in [false, true] {
        let builder = sim_builder();
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let device = Device::find("eth0");
            assert_eq!(device.restart(), (CR_SUCCESS, CR_SUCCESS));
            std::thread::sleep(Duration::from_secs(1));
            assert_eq!(device.restart(), (CR_SUCCESS, CR_SUCCESS));
            assert_eq!(
                unsafe { CM_Enable_DevNode(device.data.DevInst, 0) },
                CR_SUCCESS
            );
            std::thread::sleep(Duration::from_millis(1100));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
            std::thread::sleep(Duration::from_millis(910));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp);
        });
        assert_eq!(sim.adapter_restarts("eth0"), 2);
    }
}

#[test]
fn repeated_disable_preserves_the_original_carrier() {
    for deterministic in [false, true] {
        let builder = sim_builder();
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            let device = Device::find("eth0");
            for _ in 0..2 {
                assert_eq!(
                    unsafe { CM_Disable_DevNode(device.data.DevInst, CM_DISABLE_UI_NOT_OK) },
                    CR_SUCCESS
                );
            }
            assert_eq!(
                unsafe { CM_Enable_DevNode(device.data.DevInst, 0) },
                CR_SUCCESS
            );
            std::thread::sleep(Duration::from_millis(2010));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp);
        });
        assert_eq!(sim.adapter_restarts("eth0"), 1);
        sim.set_link("eth0", false).unwrap();
        sim.run(|| {
            let device = Device::find("eth0");
            assert_eq!(device.restart(), (CR_SUCCESS, CR_SUCCESS));
            std::thread::sleep(Duration::from_secs(3));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
        });
    }
}

#[test]
fn reconfiguring_an_adapter_cancels_its_pending_restart() {
    for deterministic in [false, true] {
        let builder = sim_builder();
        let sim = if deterministic {
            builder.deterministic().build()
        } else {
            builder.build()
        };
        sim.run(|| {
            assert_eq!(Device::find("eth0").restart(), (CR_SUCCESS, CR_SUCCESS));
            std::thread::sleep(Duration::from_secs(1));
            sim.set_adapter("eth0", Adapter::new());
            std::thread::sleep(Duration::from_secs(2));
            assert_eq!(if_row("eth0").OperStatus, IfOperStatusDown);
        });
        assert_eq!(sim.adapter_restarts("eth0"), 0);
    }
}

#[test]
fn a_standard_user_is_refused() {
    let sim = sim_builder().privileges(Privileges::none()).build();
    sim.run(|| {
        let device = Device::find("eth0");
        assert_eq!(
            device.key(DIREG_DRV, KEY_READ | KEY_SET_VALUE).err(),
            Some(ERROR_ACCESS_DENIED)
        );
        assert_eq!(
            device.key(DIREG_DEV, KEY_READ | KEY_CREATE_SUB_KEY).err(),
            Some(ERROR_ACCESS_DENIED)
        );
        let key = device.key(DIREG_DRV, KEY_READ).unwrap();
        assert_eq!(
            key.keyword("*ReceiveBuffers"),
            Ok((256, 4096)),
            "reading is allowed"
        );
        assert_eq!(
            key.set_string("*ReceiveBuffers", "64"),
            Err(ERROR_ACCESS_DENIED)
        );
        assert_eq!(key.create_subkey("x").err(), Some(ERROR_ACCESS_DENIED));
        assert_eq!(device.restart(), (CR_ACCESS_DENIED, CR_ACCESS_DENIED));
        assert_eq!(if_row("eth0").OperStatus, IfOperStatusUp);
    });
}

#[test]
fn device_parameters_hold_the_interrupt_affinity_policy() {
    let sim = sim_builder().build();
    sim.run(|| {
        let device = Device::find("eth0");
        let params = device
            .key(DIREG_DEV, KEY_READ | KEY_SET_VALUE | KEY_CREATE_SUB_KEY)
            .unwrap();
        let path = r"Interrupt Management\Affinity Policy";
        let (policy, disposition) = params.create_subkey(path).unwrap();
        assert_eq!(disposition, REG_CREATED_NEW_KEY);
        policy
            .set_value("DevicePolicy", REG_DWORD, &4u32.to_ne_bytes())
            .unwrap();
        policy
            .set_value(
                "AssignmentSetOverride",
                REG_BINARY,
                &0b1100usize.to_ne_bytes(),
            )
            .unwrap();
        assert_eq!(
            params.create_subkey(path).unwrap().1,
            REG_OPENED_EXISTING_KEY
        );
        let name = wide("DevicePolicy");
        assert_eq!(
            unsafe { RegDeleteValueW(policy.0, name.as_ptr()) },
            ERROR_SUCCESS
        );
        assert_eq!(
            unsafe { RegDeleteValueW(policy.0, name.as_ptr()) },
            ERROR_FILE_NOT_FOUND
        );
        policy
            .set_value("DevicePolicy", REG_DWORD, &4u32.to_ne_bytes())
            .unwrap();
    });
    let path = r"Interrupt Management\Affinity Policy";
    assert_eq!(
        sim.adapter_value("eth0", AdapterKey::Device, path, "devicepolicy"),
        Some(RegValue::Dword(4))
    );
    assert_eq!(
        sim.adapter_value("eth0", AdapterKey::Device, path, "AssignmentSetOverride"),
        Some(RegValue::Binary(0b1100usize.to_ne_bytes().to_vec()))
    );
    assert_eq!(
        sim.adapter_value("eth1", AdapterKey::Device, path, "DevicePolicy"),
        None
    );
}

#[test]
fn real_registry_keys_pass_through() {
    let sim = sim_builder().build();
    sim.run(|| {
        let software = wide("Software");
        let mut h: HKEY = ptr::null_mut();
        assert_eq!(
            unsafe { RegOpenKeyExW(HKEY_CURRENT_USER, software.as_ptr(), 0, KEY_READ, &mut h) },
            ERROR_SUCCESS
        );
        assert_eq!(unsafe { RegCloseKey(h) }, ERROR_SUCCESS);
    });
}

/// The registry calls' answers: a short buffer, a size query, a buffer without a length, a missing
/// value, a write through a read-only handle and a missing subkey.
fn registry_probes(key: HKEY, name: &str) -> Vec<(u32, u32, u32)> {
    let name = wide(name);
    let mut out = Vec::new();
    unsafe {
        let mut buf = [0u8; 256];
        let (mut ty, mut len) = (0u32, 2u32);
        let rc = RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            buf.as_mut_ptr(),
            &mut len,
        );
        out.push((rc, len, ty));
        let (mut ty, mut len) = (0u32, 0u32);
        let rc = RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            &mut ty,
            ptr::null_mut(),
            &mut len,
        );
        out.push((rc, len, ty));
        let rc = RegQueryValueExW(
            key,
            name.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            buf.as_mut_ptr(),
            ptr::null_mut(),
        );
        out.push((rc, 0, 0));
        let missing = wide("NoSuchValue");
        let mut len = 200u32;
        let rc = RegQueryValueExW(
            key,
            missing.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            buf.as_mut_ptr(),
            &mut len,
        );
        out.push((rc, len, 0));
        let data = [65u8, 0, 0, 0];
        let rc = RegSetValueExW(key, missing.as_ptr(), 0, REG_SZ, data.as_ptr(), 4);
        out.push((rc, 0, 0));
        let sub = wide(r"No\Such\Key");
        let mut h: HKEY = ptr::null_mut();
        let rc = RegOpenKeyExW(key, sub.as_ptr(), 0, KEY_READ, &mut h);
        out.push((rc, 0, 0));
    }
    out
}

#[test]
fn registry_codes_os_truth() {
    let value = "SnareProbe";
    let real = snare::real(|| unsafe {
        let path = wide(r"Software\snare-registry-os-truth");
        let mut writable: HKEY = ptr::null_mut();
        assert_eq!(
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                ptr::null(),
                REG_OPTION_VOLATILE,
                KEY_READ | KEY_SET_VALUE,
                ptr::null(),
                &mut writable,
                ptr::null_mut(),
            ),
            ERROR_SUCCESS
        );
        Key(writable)
            .set_string(value, "{E45CABC2-39F6-4F53-999D-F4C59C5E1250}")
            .unwrap();
        let mut read: HKEY = ptr::null_mut();
        assert_eq!(
            RegOpenKeyExW(HKEY_CURRENT_USER, path.as_ptr(), 0, KEY_READ, &mut read),
            ERROR_SUCCESS
        );
        let probes = registry_probes(read, value);
        RegCloseKey(read);
        RegDeleteKeyW(HKEY_CURRENT_USER, path.as_ptr());
        probes
    });
    let sim = sim_builder().build();
    let simulated = sim.run(|| {
        let device = Device::find("eth0");
        device
            .key(DIREG_DRV, KEY_READ | KEY_SET_VALUE)
            .unwrap()
            .set_string(value, "{E45CABC2-39F6-4F53-999D-F4C59C5E1250}")
            .unwrap();
        let key = device.key(DIREG_DRV, KEY_READ).unwrap();
        registry_probes(key.0, value)
    });
    assert_eq!(simulated, real);
    assert_eq!(
        real[0],
        (234, 78, REG_SZ),
        "ERROR_MORE_DATA with the size and type"
    );
}

/// SetupAPI's answers over the network class: enumerating past the end, a wrong `cbSize`, and an
/// invalid key type.
fn setupapi_probes() -> Vec<u32> {
    unsafe {
        let set = SetupDiGetClassDevsW(
            &GUID_DEVCLASS_NET,
            ptr::null(),
            ptr::null_mut(),
            DIGCF_PRESENT,
        );
        let mut data: SP_DEVINFO_DATA = zeroed();
        data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
        let mut n = 0;
        while SetupDiEnumDeviceInfo(set, n, &mut data) != 0 {
            n += 1;
        }
        let mut out = vec![GetLastError()];
        if n > 0 {
            let mut bad: SP_DEVINFO_DATA = zeroed();
            bad.cbSize = 3;
            assert_eq!(SetupDiEnumDeviceInfo(set, 0, &mut bad), 0);
            out.push(GetLastError());
            data.cbSize = size_of::<SP_DEVINFO_DATA>() as u32;
            assert_ne!(SetupDiEnumDeviceInfo(set, 0, &mut data), 0);
            let h = SetupDiOpenDevRegKey(set, &data, DICS_FLAG_GLOBAL, 0, 7, KEY_READ);
            assert!(ptr::eq(h, INVALID_HANDLE_VALUE));
            out.push(GetLastError());
        }
        SetupDiDestroyDeviceInfoList(set);
        out
    }
}

#[test]
fn setupapi_codes_os_truth() {
    let real = snare::real(setupapi_probes);
    let simulated = sim_builder().build().run(setupapi_probes);
    if real.len() == 1 {
        assert_eq!(simulated[0], real[0]);
        return;
    }
    assert_eq!(simulated, real);
    assert_eq!(real, vec![259, 1784, 1004]);
}

fn set_ws(min: usize, max: usize, flags: u32) -> Result<(), u32> {
    if unsafe { SetProcessWorkingSetSizeEx(GetCurrentProcess(), min, max, flags) } != 0 {
        Ok(())
    } else {
        Err(unsafe { GetLastError() })
    }
}

fn get_ws() -> (usize, usize, u32) {
    let (mut min, mut max, mut flags) = (0, 0, 0);
    assert_ne!(
        unsafe { GetProcessWorkingSetSizeEx(GetCurrentProcess(), &mut min, &mut max, &mut flags) },
        0
    );
    (min, max, flags)
}

#[test]
fn working_set_is_modelled() {
    let sim = Sim::new();
    sim.run(|| {
        assert_eq!(get_ws(), (204_800, 1_413_120, 10));
        set_ws(
            16 << 20,
            64 << 20,
            QUOTA_LIMITS_HARDWS_MIN_ENABLE | QUOTA_LIMITS_HARDWS_MAX_DISABLE,
        )
        .unwrap();
        assert_eq!(get_ws(), (16 << 20, 64 << 20, 9));
        assert_eq!(set_ws(64 << 20, 16 << 20, 0), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(set_ws(16 << 20, 64 << 20, 3), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(set_ws(16 << 20, 64 << 20, 12), Err(ERROR_INVALID_PARAMETER));
        assert_eq!(
            set_ws(15 << 30, 16 << 30, 0),
            Err(ERROR_NO_SYSTEM_RESOURCES)
        );
        set_ws(77_824, 1_413_121, 0).unwrap();
        assert_eq!(
            get_ws(),
            (81_920, 1_413_120, 9),
            "rounded, raised to 20 pages, flags kept"
        );
        set_ws(usize::MAX, usize::MAX, 0).unwrap();
        assert_eq!(get_ws().0, 81_920, "a trim changes nothing");
    });
    let ws = sim.working_set();
    assert_eq!((ws.min, ws.max), (81_920, 1_413_120));
}

#[test]
fn raising_the_working_set_needs_the_privilege() {
    let mut privileges = Privileges::all();
    privileges.ipc_lock = false;
    let sim = Sim::builder().privileges(privileges).build();
    sim.run(|| {
        assert_eq!(set_ws(16 << 20, 64 << 20, 0), Err(ERROR_PRIVILEGE_NOT_HELD));
        set_ws(102_400, 1_000_000, 0).unwrap();
        assert_eq!(get_ws(), (102_400, 999_424, 10), "lowering is allowed");
    });
    sim.set_privileges(|p| p.ipc_lock = true);
    sim.run(|| set_ws(16 << 20, 64 << 20, 0).unwrap());
}

/// The working-set answers measured on the real OS: rejected bounds and flags, and rounding.
fn working_set_probes() -> Vec<Result<(usize, usize), u32>> {
    let mut out = Vec::new();
    for (min, max, flags) in [
        (64usize << 20, 16usize << 20, 0u32),
        (16 << 20, 64 << 20, 3),
        (16 << 20, 64 << 20, 12),
        (204_801, 1_413_121, QUOTA_LIMITS_HARDWS_MAX_DISABLE),
        (77_824, 1_413_120, 0),
    ] {
        out.push(set_ws(min, max, flags).map(|()| {
            let (min, max, _) = get_ws();
            (min, max)
        }));
    }
    out
}

#[test]
fn working_set_os_truth() {
    let real = snare::real(working_set_probes);
    let simulated = Sim::new().run(working_set_probes);
    assert_eq!(simulated, real);
}
