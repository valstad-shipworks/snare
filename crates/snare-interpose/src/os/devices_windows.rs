//! The device-installation and registry calls a program uses to tune a network adapter: find its
//! device node with SetupAPI (`setupapi.dll`), read and write its advanced properties in the
//! registry (`advapi32.dll`) and restart it with the Configuration Manager (`cfgmgr32.dll`), as
//! Device Manager and `Set-NetAdapterAdvancedProperty` do. Each is offered to the domain's
//! [`Host`](crate::Host) as a [`DevCall`]; signatures follow `setupapi.h`, `cfgmgr32.h` and
//! `winreg.h`.
//!
//! The host claims only the device information sets, registry keys and device instances it
//! minted (and the network class enumeration that mints them); every other handle, key and
//! class goes to the original export untouched, so the rest of the process keeps the real
//! registry. A modelled call reports failure as the real one does: SetupAPI through the thread's
//! last error, the registry and Configuration Manager through their return value.

use std::ffi::c_void;
use std::sync::atomic::AtomicUsize;

use windows_sys::Win32::Foundation::SetLastError;

use crate::domain::dispatch_host;
use crate::hooks::{Hook, hook, original};
use crate::host::DevCall;

/// The original `SetupDiGetClassDevsW`, filled in when the hook is installed; 0 until then. Every
/// `static` below holds one export's original address the same way.
static GET_CLASS_DEVS_W: AtomicUsize = AtomicUsize::new(0);
/// The original `SetupDiEnumDeviceInfo`.
static ENUM_DEVICE_INFO: AtomicUsize = AtomicUsize::new(0);
/// The original `SetupDiDestroyDeviceInfoList`.
static DESTROY_DEVICE_INFO_LIST: AtomicUsize = AtomicUsize::new(0);
/// The original `SetupDiOpenDevRegKey`.
static OPEN_DEV_REG_KEY: AtomicUsize = AtomicUsize::new(0);
/// The original `CM_Disable_DevNode`.
static CM_DISABLE_DEV_NODE: AtomicUsize = AtomicUsize::new(0);
/// The original `CM_Enable_DevNode`.
static CM_ENABLE_DEV_NODE: AtomicUsize = AtomicUsize::new(0);
/// The original `RegOpenKeyExW`.
static REG_OPEN_KEY_EX_W: AtomicUsize = AtomicUsize::new(0);
/// The original `RegCreateKeyExW`.
static REG_CREATE_KEY_EX_W: AtomicUsize = AtomicUsize::new(0);
/// The original `RegQueryValueExW`.
static REG_QUERY_VALUE_EX_W: AtomicUsize = AtomicUsize::new(0);
/// The original `RegSetValueExW`.
static REG_SET_VALUE_EX_W: AtomicUsize = AtomicUsize::new(0);
/// The original `RegDeleteValueW`.
static REG_DELETE_VALUE_W: AtomicUsize = AtomicUsize::new(0);
/// The original `RegCloseKey`.
static REG_CLOSE_KEY: AtomicUsize = AtomicUsize::new(0);

/// `INVALID_HANDLE_VALUE`, `(HANDLE)(LONG_PTR)-1` (`handleapi.h`): what `SetupDiGetClassDevsW`
/// and `SetupDiOpenDevRegKey` return on failure
/// ([Microsoft Learn: SetupDiOpenDevRegKey](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey)).
const INVALID_HANDLE_VALUE: *mut c_void = -1isize as *mut c_void;

/// The SetupAPI, Configuration Manager and registry hooks, each naming its export's DLL (the
/// one `windows-sys` links it from), its replacement and the `static` that receives the original.
pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!(
            "SetupDiGetClassDevsW",
            "setupapi.dll",
            get_class_devs_w,
            GET_CLASS_DEVS_W
        ),
        hook!(
            "SetupDiEnumDeviceInfo",
            "setupapi.dll",
            enum_device_info,
            ENUM_DEVICE_INFO
        ),
        hook!(
            "SetupDiDestroyDeviceInfoList",
            "setupapi.dll",
            destroy_device_info_list,
            DESTROY_DEVICE_INFO_LIST
        ),
        hook!(
            "SetupDiOpenDevRegKey",
            "setupapi.dll",
            open_dev_reg_key,
            OPEN_DEV_REG_KEY
        ),
        hook!(
            "CM_Disable_DevNode",
            "cfgmgr32.dll",
            cm_disable_dev_node,
            CM_DISABLE_DEV_NODE
        ),
        hook!(
            "CM_Enable_DevNode",
            "cfgmgr32.dll",
            cm_enable_dev_node,
            CM_ENABLE_DEV_NODE
        ),
        hook!(
            "RegOpenKeyExW",
            "advapi32.dll",
            reg_open_key_ex_w,
            REG_OPEN_KEY_EX_W
        ),
        hook!(
            "RegCreateKeyExW",
            "advapi32.dll",
            reg_create_key_ex_w,
            REG_CREATE_KEY_EX_W
        ),
        hook!(
            "RegQueryValueExW",
            "advapi32.dll",
            reg_query_value_ex_w,
            REG_QUERY_VALUE_EX_W
        ),
        hook!(
            "RegSetValueExW",
            "advapi32.dll",
            reg_set_value_ex_w,
            REG_SET_VALUE_EX_W
        ),
        hook!(
            "RegDeleteValueW",
            "advapi32.dll",
            reg_delete_value_w,
            REG_DELETE_VALUE_W
        ),
        hook!("RegCloseKey", "advapi32.dll", reg_close_key, REG_CLOSE_KEY),
    ]
}

/// Offers `call` to the calling thread's host; `Some` is its answer in the raw convention
/// (`HostResult::into_raw`), `None` means call the original.
fn offer(call: DevCall<'_>) -> Option<i64> {
    // SAFETY: the pointers in `call` are the caller's, passed through unchanged.
    dispatch_host(|host| unsafe { host.device(call) })
}

/// The NUL-terminated wide string at `p`, without its terminator; `None` for null.
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

/// A SetupAPI handle result: the value, or `INVALID_HANDLE_VALUE` with the last error set.
fn finish_handle(r: i64) -> *mut c_void {
    if r < 0 {
        // SAFETY: setting the calling thread's last error.
        unsafe { SetLastError((-r) as u32) };
        INVALID_HANDLE_VALUE
    } else {
        r as usize as *mut c_void
    }
}

/// A SetupAPI `BOOL` result: `TRUE`, or `FALSE` with the last error set.
fn finish_bool(r: i64) -> i32 {
    if r < 0 {
        // SAFETY: setting the calling thread's last error.
        unsafe { SetLastError((-r) as u32) };
        0
    } else {
        r as i32
    }
}

/// `SetupDiGetClassDevsW`: a device information set for a class
/// ([Microsoft Learn: SetupDiGetClassDevsW](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdigetclassdevsw)).
unsafe extern "system" fn get_class_devs_w(
    class: *const [u8; 16],
    enumerator: *const u16,
    parent: *mut c_void,
    flags: u32,
) -> *mut c_void {
    // SAFETY: a non-null class points at a GUID; the enumerator is null or a C string.
    let call = DevCall::GetClassDevs {
        class: unsafe { class.as_ref() },
        enumerator: unsafe { wide(enumerator) },
        flags,
    };
    if let Some(r) = offer(call) {
        return finish_handle(r);
    }
    // SAFETY: GET_CLASS_DEVS_W holds setupapi's SetupDiGetClassDevsW.
    unsafe {
        original::<
            unsafe extern "system" fn(*const [u8; 16], *const u16, *mut c_void, u32) -> *mut c_void,
        >(&GET_CLASS_DEVS_W)(class, enumerator, parent, flags)
    }
}

/// `SetupDiEnumDeviceInfo`: the `index`th device of a set, `ERROR_NO_MORE_ITEMS` past the end
/// ([Microsoft Learn: SetupDiEnumDeviceInfo](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdienumdeviceinfo)).
unsafe extern "system" fn enum_device_info(set: *mut c_void, index: u32, data: *mut u8) -> i32 {
    if let Some(r) = offer(DevCall::EnumDeviceInfo {
        set: set as u64,
        index,
        data,
    }) {
        return finish_bool(r);
    }
    // SAFETY: ENUM_DEVICE_INFO holds setupapi's SetupDiEnumDeviceInfo.
    unsafe {
        original::<unsafe extern "system" fn(*mut c_void, u32, *mut u8) -> i32>(&ENUM_DEVICE_INFO)(
            set, index, data,
        )
    }
}

/// `SetupDiDestroyDeviceInfoList`: frees a set
/// ([Microsoft Learn: SetupDiDestroyDeviceInfoList](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdidestroydeviceinfolist)).
unsafe extern "system" fn destroy_device_info_list(set: *mut c_void) -> i32 {
    if let Some(r) = offer(DevCall::DestroyDeviceInfoList { set: set as u64 }) {
        return finish_bool(r);
    }
    // SAFETY: DESTROY_DEVICE_INFO_LIST holds setupapi's SetupDiDestroyDeviceInfoList.
    unsafe {
        original::<unsafe extern "system" fn(*mut c_void) -> i32>(&DESTROY_DEVICE_INFO_LIST)(set)
    }
}

/// `SetupDiOpenDevRegKey`: a device's hardware (`DIREG_DEV`) or software (`DIREG_DRV`) key
/// ([Microsoft Learn: SetupDiOpenDevRegKey](https://learn.microsoft.com/en-us/windows/win32/api/setupapi/nf-setupapi-setupdiopendevregkey)).
unsafe extern "system" fn open_dev_reg_key(
    set: *mut c_void,
    data: *const u8,
    scope: u32,
    profile: u32,
    key_type: u32,
    access: u32,
) -> *mut c_void {
    if let Some(r) = offer(DevCall::OpenDevRegKey {
        set: set as u64,
        data,
        scope,
        profile,
        key_type,
        access,
    }) {
        return finish_handle(r);
    }
    // SAFETY: OPEN_DEV_REG_KEY holds setupapi's SetupDiOpenDevRegKey.
    unsafe {
        original::<
            unsafe extern "system" fn(*mut c_void, *const u8, u32, u32, u32, u32) -> *mut c_void,
        >(&OPEN_DEV_REG_KEY)(set, data, scope, profile, key_type, access)
    }
}

/// `CM_Disable_DevNode`: disables a device instance, returning a `CONFIGRET`
/// ([Microsoft Learn: CM_Disable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_disable_devnode)).
unsafe extern "system" fn cm_disable_dev_node(devinst: u32, flags: u32) -> u32 {
    if let Some(r) = offer(DevCall::DisableDevNode { devinst, flags }) {
        return r as u32;
    }
    // SAFETY: CM_DISABLE_DEV_NODE holds cfgmgr32's CM_Disable_DevNode.
    unsafe {
        original::<unsafe extern "system" fn(u32, u32) -> u32>(&CM_DISABLE_DEV_NODE)(devinst, flags)
    }
}

/// `CM_Enable_DevNode`: enables a device instance, returning a `CONFIGRET`
/// ([Microsoft Learn: CM_Enable_DevNode](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/nf-cfgmgr32-cm_enable_devnode)).
unsafe extern "system" fn cm_enable_dev_node(devinst: u32, flags: u32) -> u32 {
    if let Some(r) = offer(DevCall::EnableDevNode { devinst, flags }) {
        return r as u32;
    }
    // SAFETY: CM_ENABLE_DEV_NODE holds cfgmgr32's CM_Enable_DevNode.
    unsafe {
        original::<unsafe extern "system" fn(u32, u32) -> u32>(&CM_ENABLE_DEV_NODE)(devinst, flags)
    }
}

/// `RegOpenKeyExW`: opens a subkey, returning an `LSTATUS`
/// ([Microsoft Learn: RegOpenKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regopenkeyexw)).
unsafe extern "system" fn reg_open_key_ex_w(
    key: *mut c_void,
    subkey: *const u16,
    options: u32,
    access: u32,
    result: *mut *mut c_void,
) -> u32 {
    // SAFETY: the subkey is null or a C string.
    let call = DevCall::OpenKey {
        key: key as u64,
        subkey: unsafe { wide(subkey) },
        access,
        result: result.cast(),
    };
    if let Some(r) = offer(call) {
        return r as u32;
    }
    // SAFETY: REG_OPEN_KEY_EX_W holds advapi32's RegOpenKeyExW.
    unsafe {
        original::<
            unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *mut *mut c_void) -> u32,
        >(&REG_OPEN_KEY_EX_W)(key, subkey, options, access, result)
    }
}

/// `RegCreateKeyExW`: creates or opens a subkey, returning an `LSTATUS`
/// ([Microsoft Learn: RegCreateKeyExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regcreatekeyexw)).
#[allow(clippy::too_many_arguments)]
unsafe extern "system" fn reg_create_key_ex_w(
    key: *mut c_void,
    subkey: *const u16,
    reserved: u32,
    class: *const u16,
    options: u32,
    access: u32,
    security: *const c_void,
    result: *mut *mut c_void,
    disposition: *mut u32,
) -> u32 {
    // SAFETY: the subkey is null or a C string.
    let call = DevCall::CreateKey {
        key: key as u64,
        subkey: unsafe { wide(subkey) },
        access,
        result: result.cast(),
        disposition,
    };
    if let Some(r) = offer(call) {
        return r as u32;
    }
    type F = unsafe extern "system" fn(
        *mut c_void,
        *const u16,
        u32,
        *const u16,
        u32,
        u32,
        *const c_void,
        *mut *mut c_void,
        *mut u32,
    ) -> u32;
    // SAFETY: REG_CREATE_KEY_EX_W holds advapi32's RegCreateKeyExW.
    unsafe {
        original::<F>(&REG_CREATE_KEY_EX_W)(
            key,
            subkey,
            reserved,
            class,
            options,
            access,
            security,
            result,
            disposition,
        )
    }
}

/// `RegQueryValueExW`: a value's type and data, returning an `LSTATUS`
/// ([Microsoft Learn: RegQueryValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryvalueexw)).
unsafe extern "system" fn reg_query_value_ex_w(
    key: *mut c_void,
    name: *const u16,
    reserved: *const u32,
    ty: *mut u32,
    data: *mut u8,
    len: *mut u32,
) -> u32 {
    // SAFETY: the name is null or a C string.
    let call = DevCall::QueryValue {
        key: key as u64,
        name: unsafe { wide(name) },
        ty,
        data,
        len,
    };
    if let Some(r) = offer(call) {
        return r as u32;
    }
    // SAFETY: REG_QUERY_VALUE_EX_W holds advapi32's RegQueryValueExW.
    unsafe {
        original::<
            unsafe extern "system" fn(
                *mut c_void,
                *const u16,
                *const u32,
                *mut u32,
                *mut u8,
                *mut u32,
            ) -> u32,
        >(&REG_QUERY_VALUE_EX_W)(key, name, reserved, ty, data, len)
    }
}

/// `RegSetValueExW`: stores a value, returning an `LSTATUS`
/// ([Microsoft Learn: RegSetValueExW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regsetvalueexw)).
unsafe extern "system" fn reg_set_value_ex_w(
    key: *mut c_void,
    name: *const u16,
    reserved: u32,
    ty: u32,
    data: *const u8,
    len: u32,
) -> u32 {
    // SAFETY: the name is null or a C string.
    let call = DevCall::SetValue {
        key: key as u64,
        name: unsafe { wide(name) },
        ty,
        data,
        len,
    };
    if let Some(r) = offer(call) {
        return r as u32;
    }
    // SAFETY: REG_SET_VALUE_EX_W holds advapi32's RegSetValueExW.
    unsafe {
        original::<
            unsafe extern "system" fn(*mut c_void, *const u16, u32, u32, *const u8, u32) -> u32,
        >(&REG_SET_VALUE_EX_W)(key, name, reserved, ty, data, len)
    }
}

/// `RegDeleteValueW`: removes a value, returning an `LSTATUS`
/// ([Microsoft Learn: RegDeleteValueW](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regdeletevaluew)).
unsafe extern "system" fn reg_delete_value_w(key: *mut c_void, name: *const u16) -> u32 {
    // SAFETY: the name is null or a C string.
    let call = DevCall::DeleteValue {
        key: key as u64,
        name: unsafe { wide(name) },
    };
    if let Some(r) = offer(call) {
        return r as u32;
    }
    // SAFETY: REG_DELETE_VALUE_W holds advapi32's RegDeleteValueW.
    unsafe {
        original::<unsafe extern "system" fn(*mut c_void, *const u16) -> u32>(&REG_DELETE_VALUE_W)(
            key, name,
        )
    }
}

/// `RegCloseKey`: releases a key handle, returning an `LSTATUS`
/// ([Microsoft Learn: RegCloseKey](https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regclosekey)).
unsafe extern "system" fn reg_close_key(key: *mut c_void) -> u32 {
    if let Some(r) = offer(DevCall::CloseKey { key: key as u64 }) {
        return r as u32;
    }
    // SAFETY: REG_CLOSE_KEY holds advapi32's RegCloseKey.
    unsafe { original::<unsafe extern "system" fn(*mut c_void) -> u32>(&REG_CLOSE_KEY)(key) }
}
