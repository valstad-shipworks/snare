use std::collections::{HashMap, VecDeque};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};

use windows_sys::Win32::Foundation::{GetLastError, SetLastError};

use windows_sys::Win32::System::Threading::CRITICAL_SECTION;

use crate::domain;
use crate::hooks::{Hook, hook, original};

type Lock = unsafe extern "system" fn(*mut c_void);
type Try = unsafe extern "system" fn(*mut c_void) -> bool;
type TryCritical = unsafe extern "system" fn(*mut c_void) -> i32;

static ENTER_CRITICAL_SECTION: AtomicUsize = AtomicUsize::new(0);
static TRY_ENTER_CRITICAL_SECTION: AtomicUsize = AtomicUsize::new(0);
static LEAVE_CRITICAL_SECTION: AtomicUsize = AtomicUsize::new(0);
static ACQUIRE_SRW_EXCLUSIVE: AtomicUsize = AtomicUsize::new(0);
static TRY_ACQUIRE_SRW_EXCLUSIVE: AtomicUsize = AtomicUsize::new(0);
static RELEASE_SRW_EXCLUSIVE: AtomicUsize = AtomicUsize::new(0);
static ACQUIRE_SRW_SHARED: AtomicUsize = AtomicUsize::new(0);
static TRY_ACQUIRE_SRW_SHARED: AtomicUsize = AtomicUsize::new(0);
static RELEASE_SRW_SHARED: AtomicUsize = AtomicUsize::new(0);
static SLEEP_CONDITION_CS: AtomicUsize = AtomicUsize::new(0);
static SLEEP_CONDITION_SRW: AtomicUsize = AtomicUsize::new(0);
static WAKE_CONDITION: AtomicUsize = AtomicUsize::new(0);
static WAKE_ALL_CONDITION: AtomicUsize = AtomicUsize::new(0);

pub(super) fn hooks() -> Vec<Hook> {
    vec![
        hook!(
            "EnterCriticalSection",
            "kernel32.dll",
            enter_critical_section,
            ENTER_CRITICAL_SECTION
        ),
        hook!(
            "TryEnterCriticalSection",
            "kernel32.dll",
            try_enter_critical_section,
            TRY_ENTER_CRITICAL_SECTION
        ),
        hook!(
            "LeaveCriticalSection",
            "kernel32.dll",
            leave_critical_section,
            LEAVE_CRITICAL_SECTION
        ),
        hook!(
            "AcquireSRWLockExclusive",
            "kernel32.dll",
            acquire_srw_exclusive,
            ACQUIRE_SRW_EXCLUSIVE
        ),
        hook!(
            "TryAcquireSRWLockExclusive",
            "kernel32.dll",
            try_acquire_srw_exclusive,
            TRY_ACQUIRE_SRW_EXCLUSIVE
        ),
        hook!(
            "ReleaseSRWLockExclusive",
            "kernel32.dll",
            release_srw_exclusive,
            RELEASE_SRW_EXCLUSIVE
        ),
        hook!(
            "AcquireSRWLockShared",
            "kernel32.dll",
            acquire_srw_shared,
            ACQUIRE_SRW_SHARED
        ),
        hook!(
            "TryAcquireSRWLockShared",
            "kernel32.dll",
            try_acquire_srw_shared,
            TRY_ACQUIRE_SRW_SHARED
        ),
        hook!(
            "ReleaseSRWLockShared",
            "kernel32.dll",
            release_srw_shared,
            RELEASE_SRW_SHARED
        ),
        hook!(
            "SleepConditionVariableCS",
            "kernel32.dll",
            sleep_condition_cs,
            SLEEP_CONDITION_CS
        ),
        hook!(
            "SleepConditionVariableSRW",
            "kernel32.dll",
            sleep_condition_srw,
            SLEEP_CONDITION_SRW
        ),
        hook!(
            "WakeConditionVariable",
            "kernel32.dll",
            wake_condition,
            WAKE_CONDITION
        ),
        hook!(
            "WakeAllConditionVariable",
            "kernel32.dll",
            wake_all_condition,
            WAKE_ALL_CONDITION
        ),
    ]
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Mode {
    Critical,
    Exclusive,
    Shared,
}

fn lock_waiters() -> &'static Mutex<HashMap<usize, Vec<Weak<AtomicU32>>>> {
    static WAITERS: OnceLock<Mutex<HashMap<usize, Vec<Weak<AtomicU32>>>>> = OnceLock::new();
    WAITERS.get_or_init(Mutex::default)
}

struct LockWaiter {
    lock: usize,
    word: Arc<AtomicU32>,
}

impl LockWaiter {
    fn new(lock: usize) -> Self {
        let _pass = crate::state::Passthrough::enter();
        let word = Arc::new(AtomicU32::new(0));
        lock_waiters()
            .lock()
            .unwrap()
            .entry(lock)
            .or_default()
            .push(Arc::downgrade(&word));
        Self { lock, word }
    }
}

impl Drop for LockWaiter {
    fn drop(&mut self) {
        let _pass = crate::state::Passthrough::enter();
        let mut waiters = lock_waiters().lock().unwrap();
        if let Some(words) = waiters.get_mut(&self.lock) {
            let weak = Arc::downgrade(&self.word);
            words.retain(|word| !Weak::ptr_eq(word, &weak));
            if words.is_empty() {
                waiters.remove(&self.lock);
            }
        }
    }
}

fn notify_lock_waiters(lock: usize) {
    thread_local! {
        static NOTIFYING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    }
    if NOTIFYING.with(|notifying| notifying.replace(true)) {
        return;
    }
    struct Notify;
    impl Drop for Notify {
        fn drop(&mut self) {
            NOTIFYING.with(|notifying| notifying.set(false));
        }
    }
    let _notify = Notify;
    let words: Vec<_> = {
        let _pass = crate::state::Passthrough::enter();
        lock_waiters()
            .lock()
            .unwrap()
            .get(&lock)
            .into_iter()
            .flatten()
            .filter_map(Weak::upgrade)
            .collect()
    };
    for word in words {
        word.fetch_add(1, Ordering::Release);
        unsafe { super::wake_by_address_single(Arc::as_ptr(&word).cast()) };
    }
}

unsafe fn taken(lock: *mut c_void, mode: Mode) {
    let addr = lock as usize;
    let recorded = crate::accounting::held().is_some_and(|held| held.holds(addr));
    if mode == Mode::Shared {
        domain::note_shared_mutex(addr, true);
        if domain::counts_native_waits() && domain::det_active() {
            domain::det_took_shared(addr);
        }
    } else if mode != Mode::Critical || !recorded {
        domain::note_mutex_taken(addr);
        if domain::counts_native_waits() && domain::det_active() {
            domain::det_took(addr);
        }
    }
}

unsafe fn try_take(lock: *mut c_void, mode: Mode) -> bool {
    let acquired = if mode == Mode::Critical {
        (unsafe { original::<TryCritical>(&TRY_ENTER_CRITICAL_SECTION)(lock) }) != 0
    } else {
        unsafe {
            original::<Try>(if mode == Mode::Shared {
                &TRY_ACQUIRE_SRW_SHARED
            } else {
                &TRY_ACQUIRE_SRW_EXCLUSIVE
            })(lock)
        }
    };
    if acquired {
        unsafe { taken(lock, mode) };
    }
    acquired
}

unsafe fn release(lock: *mut c_void, mode: Mode) {
    let last =
        mode != Mode::Critical || unsafe { (*lock.cast::<CRITICAL_SECTION>()).RecursionCount } == 1;
    let slot = match mode {
        Mode::Critical => &LEAVE_CRITICAL_SECTION,
        Mode::Exclusive => &RELEASE_SRW_EXCLUSIVE,
        Mode::Shared => &RELEASE_SRW_SHARED,
    };
    unsafe { original::<Lock>(slot)(lock) };
    if last {
        if mode == Mode::Shared {
            domain::note_shared_mutex(lock as usize, false);
        } else {
            domain::note_mutex_freed(lock as usize);
        }
        if domain::det_wakes() {
            if mode == Mode::Shared {
                domain::det_released_shared(lock as usize);
            } else {
                domain::det_released(lock as usize);
            }
            domain::det_wake(crate::DetKey::Addr(lock as usize), usize::MAX);
        }
        notify_lock_waiters(lock as usize);
    }
}

unsafe fn acquire(lock: *mut c_void, mode: Mode) {
    let slot = match mode {
        Mode::Critical => &ENTER_CRITICAL_SECTION,
        Mode::Exclusive => &ACQUIRE_SRW_EXCLUSIVE,
        Mode::Shared => &ACQUIRE_SRW_SHARED,
    };
    let native = unsafe { original::<Lock>(slot) };
    if !domain::counts_native_waits() {
        unsafe {
            native(lock);
            taken(lock, mode);
        }
        return;
    }
    if unsafe { try_take(lock, mode) } {
        return;
    }
    let addr = lock as usize;
    if domain::det_active() {
        loop {
            if domain::det_held_inside(addr) {
                let _label = crate::accounting::wait_label_mutex("Windows lock", None, addr);
                domain::det_block(crate::DetKey::Addr(addr), None);
            } else {
                domain::end_spin();
                unsafe {
                    native(lock);
                    taken(lock, mode);
                }
                return;
            }
            if unsafe { try_take(lock, mode) } {
                return;
            }
        }
    }
    let _watch = domain::watch_mutex(addr, false);
    let waiter = LockWaiter::new(addr);
    loop {
        let expected = waiter.word.load(Ordering::Acquire);
        if unsafe { try_take(lock, mode) } {
            return;
        }
        if !domain::mutex_held_inside(addr) {
            break;
        }
        unsafe {
            super::wait_on_address(
                Arc::as_ptr(&waiter.word).cast(),
                std::ptr::from_ref(&expected).cast(),
                4,
                u32::MAX,
            );
        }
    }
    if unsafe { try_take(lock, mode) } {
        return;
    }
    let _label = crate::accounting::wait_label_mutex("Windows lock", None, addr);
    let relock = |take| unsafe {
        if take {
            native(lock);
            taken(lock, mode);
        } else {
            release(lock, mode);
        }
    };
    domain::native_cond_wait(&relock, || unsafe {
        native(lock);
        taken(lock, mode);
    });
}

unsafe extern "system" fn enter_critical_section(section: *mut c_void) {
    unsafe { acquire(section, Mode::Critical) };
}

unsafe extern "system" fn try_enter_critical_section(section: *mut c_void) -> i32 {
    i32::from(unsafe { try_take(section, Mode::Critical) })
}

unsafe extern "system" fn leave_critical_section(section: *mut c_void) {
    unsafe { release(section, Mode::Critical) };
}

unsafe extern "system" fn acquire_srw_exclusive(lock: *mut c_void) {
    unsafe { acquire(lock, Mode::Exclusive) };
}

unsafe extern "system" fn try_acquire_srw_exclusive(lock: *mut c_void) -> bool {
    unsafe { try_take(lock, Mode::Exclusive) }
}

unsafe extern "system" fn release_srw_exclusive(lock: *mut c_void) {
    unsafe { release(lock, Mode::Exclusive) };
}

unsafe extern "system" fn acquire_srw_shared(lock: *mut c_void) {
    unsafe { acquire(lock, Mode::Shared) };
}

unsafe extern "system" fn try_acquire_srw_shared(lock: *mut c_void) -> bool {
    unsafe { try_take(lock, Mode::Shared) }
}

unsafe extern "system" fn release_srw_shared(lock: *mut c_void) {
    unsafe { release(lock, Mode::Shared) };
}

fn conditions() -> &'static Mutex<HashMap<usize, VecDeque<Arc<AtomicU8>>>> {
    static CONDITIONS: OnceLock<Mutex<HashMap<usize, VecDeque<Arc<AtomicU8>>>>> = OnceLock::new();
    CONDITIONS.get_or_init(Mutex::default)
}

unsafe fn condition_wait(
    condition: *mut c_void,
    lock: *mut c_void,
    timeout: u32,
    mode: Mode,
) -> i32 {
    let word = Arc::new(AtomicU8::new(0));
    {
        let _pass = crate::state::Passthrough::enter();
        let mut conditions = conditions().lock().unwrap();
        conditions
            .entry(condition as usize)
            .or_default()
            .push_back(word.clone());
        drop(_pass);
        unsafe { release(lock, mode) };
        let _pass = crate::state::Passthrough::enter();
        drop(conditions);
    }
    let expected = 0u8;
    let result = unsafe {
        super::wait_on_address(
            Arc::as_ptr(&word).cast_mut().cast(),
            std::ptr::from_ref(&expected).cast(),
            1,
            timeout,
        )
    };
    let error = unsafe { GetLastError() };
    {
        let _pass = crate::state::Passthrough::enter();
        let mut conditions = conditions().lock().unwrap();
        if let Some(waiters) = conditions.get_mut(&(condition as usize)) {
            waiters.retain(|waiter| !Arc::ptr_eq(waiter, &word));
            if waiters.is_empty() {
                conditions.remove(&(condition as usize));
            }
        }
    }
    unsafe {
        acquire(lock, mode);
        SetLastError(error);
    }
    result
}

unsafe extern "system" fn sleep_condition_cs(
    condition: *mut c_void,
    lock: *mut c_void,
    timeout: u32,
) -> i32 {
    if !domain::virtual_waits() {
        return unsafe {
            original::<unsafe extern "system" fn(*mut c_void, *mut c_void, u32) -> i32>(
                &SLEEP_CONDITION_CS,
            )(condition, lock, timeout)
        };
    }
    unsafe { condition_wait(condition, lock, timeout, Mode::Critical) }
}

unsafe extern "system" fn sleep_condition_srw(
    condition: *mut c_void,
    lock: *mut c_void,
    timeout: u32,
    flags: u32,
) -> i32 {
    if !domain::virtual_waits() || flags & !1 != 0 {
        return unsafe {
            original::<unsafe extern "system" fn(*mut c_void, *mut c_void, u32, u32) -> i32>(
                &SLEEP_CONDITION_SRW,
            )(condition, lock, timeout, flags)
        };
    }
    unsafe {
        condition_wait(
            condition,
            lock,
            timeout,
            if flags == 1 {
                Mode::Shared
            } else {
                Mode::Exclusive
            },
        )
    }
}

unsafe fn condition_wake(condition: *mut c_void, all: bool) {
    let waiters = {
        let _pass = crate::state::Passthrough::enter();
        let mut conditions = conditions().lock().unwrap();
        if all {
            conditions
                .remove(&(condition as usize))
                .map_or_else(Vec::new, |q| q.into_iter().collect())
        } else {
            conditions
                .get_mut(&(condition as usize))
                .and_then(VecDeque::pop_front)
                .into_iter()
                .collect()
        }
    };
    if all || waiters.is_empty() {
        let slot = if all {
            &WAKE_ALL_CONDITION
        } else {
            &WAKE_CONDITION
        };
        unsafe { original::<Lock>(slot)(condition) };
    }
    for word in waiters {
        word.store(1, Ordering::Release);
        unsafe { super::wake_by_address_single(Arc::as_ptr(&word).cast()) };
    }
}

unsafe extern "system" fn wake_condition(condition: *mut c_void) {
    unsafe { condition_wake(condition, false) };
}

unsafe extern "system" fn wake_all_condition(condition: *mut c_void) {
    unsafe { condition_wake(condition, true) };
}
