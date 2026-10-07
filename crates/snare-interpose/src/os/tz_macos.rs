//! CoreFoundation's system time zone for a sim that decides its own zone (see [`crate::os::tz`]).
//!
//! `CFTimeZoneCopySystem` builds the zone inside CoreFoundation, from `TZ` and the
//! `/etc/localtime` link, through calls the shared cache makes and no hook sees. A program's own
//! imports of it, and of `CFTimeZoneCopyDefault` and `CFTimeZoneResetSystem`, are hooked instead,
//! so iana-time-zone and other CoreFoundation readers see the sim's zone. The CoreFoundation
//! functions that build the replacement are looked up at run time: a program that imports these
//! hooks has CoreFoundation loaded, and one that does not never reaches them.

use std::ffi::c_void;
use std::sync::atomic::AtomicUsize;

use crate::hooks::{Hook, hook, original};
use crate::race::RaceCell;

static CF_TIME_ZONE_COPY_SYSTEM: AtomicUsize = AtomicUsize::new(0);
static CF_TIME_ZONE_COPY_DEFAULT: AtomicUsize = AtomicUsize::new(0);
static CF_TIME_ZONE_RESET_SYSTEM: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn hooks() -> Vec<Hook> {
    vec![
        hook!(
            "CFTimeZoneCopySystem",
            cf_time_zone_copy_system,
            CF_TIME_ZONE_COPY_SYSTEM
        ),
        hook!(
            "CFTimeZoneCopyDefault",
            cf_time_zone_copy_default,
            CF_TIME_ZONE_COPY_DEFAULT
        ),
        hook!(
            "CFTimeZoneResetSystem",
            cf_time_zone_reset_system,
            CF_TIME_ZONE_RESET_SYSTEM
        ),
    ]
}

type CfRef = *const c_void;

type CreateWithName = unsafe extern "C" fn(CfRef, CfRef, u8) -> CfRef;
type Create = unsafe extern "C" fn(CfRef, CfRef, CfRef) -> CfRef;
type CreateFromGmt = unsafe extern "C" fn(CfRef, f64) -> CfRef;
type StringFromBytes = unsafe extern "C" fn(CfRef, *const u8, isize, u32, u8) -> CfRef;
type DataFromBytes = unsafe extern "C" fn(CfRef, *const u8, isize) -> CfRef;
type Release = unsafe extern "C" fn(CfRef);

/// The CoreFoundation functions a zone is built with (Apple Developer Documentation: Core
/// Foundation, CFTimeZone, CFString, CFData, CFType).
struct Cf {
    create_with_name: CreateWithName,
    create: Create,
    create_from_gmt: CreateFromGmt,
    string: StringFromBytes,
    data: DataFromBytes,
    release: Release,
}

/// `kCFStringEncodingUTF8` (`<CoreFoundation/CFString.h>`).
const UTF8: u32 = 0x0800_0100;

fn cf() -> Option<&'static Cf> {
    static CF: RaceCell<Option<Cf>> = RaceCell::new();
    CF.get_or_init(|| {
        let find = |name: &std::ffi::CStr| {
            // SAFETY: a C string; RTLD_DEFAULT searches every loaded image.
            let f = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
            (!f.is_null()).then_some(f)
        };
        // SAFETY: each symbol is the CoreFoundation function of the signature it is cast to.
        unsafe {
            Some(Cf {
                create_with_name: std::mem::transmute::<*mut c_void, CreateWithName>(find(
                    c"CFTimeZoneCreateWithName",
                )?),
                create: std::mem::transmute::<*mut c_void, Create>(find(c"CFTimeZoneCreate")?),
                create_from_gmt: std::mem::transmute::<*mut c_void, CreateFromGmt>(find(
                    c"CFTimeZoneCreateWithTimeIntervalFromGMT",
                )?),
                string: std::mem::transmute::<*mut c_void, StringFromBytes>(find(
                    c"CFStringCreateWithBytes",
                )?),
                data: std::mem::transmute::<*mut c_void, DataFromBytes>(find(c"CFDataCreate")?),
                release: std::mem::transmute::<*mut c_void, Release>(find(c"CFRelease")?),
            })
        }
    })
    .0
    .as_ref()
}

/// A new CFTimeZone for the calling thread's sim zone, or `None` when the sim does not decide
/// it. A zone with an IANA name is the system database's zone of that name, as CoreFoundation
/// makes it from `TZ` or the `/etc/localtime` link; failing that, one built from the sim's TZif
/// bytes; and a POSIX TZ string's zone is its standard offset, since CoreFoundation zones carry
/// no POSIX rules.
fn sim_zone() -> Option<CfRef> {
    let resolved = crate::os::tz::current(false)?;
    let _passthrough = crate::state::Passthrough::enter();
    let cf = cf()?;
    let name = resolved.name.as_deref().unwrap_or("localtime");
    // SAFETY: CoreFoundation calls with valid arguments; each object made here is released here
    // or returned at +1, as the Copy rule wants.
    unsafe {
        let string = (cf.string)(
            std::ptr::null(),
            name.as_ptr(),
            name.len() as isize,
            UTF8,
            0,
        );
        if string.is_null() {
            return None;
        }
        let mut zone = std::ptr::null();
        if resolved.name.is_some() {
            zone = (cf.create_with_name)(std::ptr::null(), string, 1);
        }
        if zone.is_null()
            && let Some(bytes) = &resolved.data
        {
            let data = (cf.data)(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize);
            if !data.is_null() {
                zone = (cf.create)(std::ptr::null(), string, data);
                (cf.release)(data);
            }
        }
        (cf.release)(string);
        if zone.is_null() {
            let utoff = resolved.zone.standard().utoff;
            zone = (cf.create_from_gmt)(std::ptr::null(), f64::from(utoff));
        }
        (!zone.is_null()).then_some(zone)
    }
}

/// `CFTimeZoneCopySystem`: the sim's zone when it decides one.
unsafe extern "C" fn cf_time_zone_copy_system() -> CfRef {
    if let Some(zone) = sim_zone() {
        return zone;
    }
    // SAFETY: CF_TIME_ZONE_COPY_SYSTEM holds CoreFoundation's CFTimeZoneCopySystem.
    unsafe { original::<unsafe extern "C" fn() -> CfRef>(&CF_TIME_ZONE_COPY_SYSTEM)() }
}

/// `CFTimeZoneCopyDefault`: the default zone is the system zone until a program sets one with
/// `CFTimeZoneSetDefault`, which is process-wide and so not the sim's to model; a sim that
/// decides its zone gets it here too.
unsafe extern "C" fn cf_time_zone_copy_default() -> CfRef {
    if let Some(zone) = sim_zone() {
        return zone;
    }
    // SAFETY: CF_TIME_ZONE_COPY_DEFAULT holds CoreFoundation's CFTimeZoneCopyDefault.
    unsafe { original::<unsafe extern "C" fn() -> CfRef>(&CF_TIME_ZONE_COPY_DEFAULT)() }
}

/// `CFTimeZoneResetSystem`: drops CoreFoundation's cached system zone. A sim that decides its
/// zone resolves it again instead, leaving the process's cache alone.
unsafe extern "C" fn cf_time_zone_reset_system() {
    if crate::domain::time_zone_setting().is_some() {
        crate::os::tz::invalidate();
        return;
    }
    // SAFETY: CF_TIME_ZONE_RESET_SYSTEM holds CoreFoundation's CFTimeZoneResetSystem.
    unsafe { original::<unsafe extern "C" fn()>(&CF_TIME_ZONE_RESET_SYSTEM)() }
}
