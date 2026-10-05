use std::collections::{BTreeSet, HashMap};
use std::ffi::c_void;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::task::{Wake, Waker};
use std::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED, HANDLE, SetLastError,
};
use windows_sys::Win32::System::Threading::{
    CreateEventExW, ResetEvent, SetEvent, TIMER_ALL_ACCESS,
};

use crate::domain::{self, Domain, WeakDomain};
use crate::hooks::{Hook, hook, original};
use crate::state::{self, Passthrough};

static CREATE: AtomicUsize = AtomicUsize::new(0);
static CREATE_EX_A: AtomicUsize = AtomicUsize::new(0);
static CREATE_W: AtomicUsize = AtomicUsize::new(0);
static CREATE_A: AtomicUsize = AtomicUsize::new(0);
static SET: AtomicUsize = AtomicUsize::new(0);
static CANCEL: AtomicUsize = AtomicUsize::new(0);
static CLOSE: AtomicUsize = AtomicUsize::new(0);
static SET_EX: AtomicUsize = AtomicUsize::new(0);
static DUPLICATE: AtomicUsize = AtomicUsize::new(0);
static WAIT_MANY: AtomicUsize = AtomicUsize::new(0);
static WAIT_MANY_EX: AtomicUsize = AtomicUsize::new(0);
static WAIT_EX: AtomicUsize = AtomicUsize::new(0);

struct Timer {
    manual: bool,
    owner: WeakDomain,
    state: Mutex<TimerState>,
}

#[derive(Default)]
struct TimerState {
    generation: u64,
    deadline: Option<Duration>,
    wake: Option<u64>,
    closed: bool,
    handles: BTreeSet<usize>,
    period: Option<Duration>,
    foreign: bool,
    groups: Vec<Weak<WaitGroup>>,
}

#[derive(Default)]
struct WaitGroup(AtomicU32);

struct GroupRegistration {
    group: Arc<WaitGroup>,
    timers: Vec<Arc<Timer>>,
}

impl Drop for GroupRegistration {
    fn drop(&mut self) {
        let _pass = Passthrough::enter();
        let weak = Arc::downgrade(&self.group);
        for timer in &self.timers {
            timer
                .state
                .lock()
                .unwrap()
                .groups
                .retain(|group| !Weak::ptr_eq(group, &weak));
        }
    }
}

fn table() -> &'static Mutex<HashMap<usize, Arc<Timer>>> {
    static TABLE: OnceLock<Mutex<HashMap<usize, Arc<Timer>>>> = OnceLock::new();
    TABLE.get_or_init(Mutex::default)
}

fn lookup(handle: HANDLE) -> Option<Arc<Timer>> {
    let _pass = Passthrough::enter();
    table().lock().unwrap().get(&(handle as usize)).cloned()
}

fn unsupported() -> i32 {
    unsafe { SetLastError(ERROR_NOT_SUPPORTED) };
    0
}

fn signal_event(handle: HANDLE, manual: bool) -> usize {
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtSetEvent(handle: HANDLE, previous: *mut i32) -> i32;
    }
    let mut previous = 0;
    let status = unsafe { NtSetEvent(handle, &mut previous) };
    if status < 0 || previous != 0 {
        0
    } else if manual {
        usize::MAX
    } else {
        1
    }
}

fn probe_timer(
    timer: &Timer,
    handle: HANDLE,
    native: unsafe extern "system" fn(HANDLE, u32) -> u32,
) -> u32 {
    let Some(owner) = timer.owner.upgrade() else {
        return unsafe { native(handle, 0) };
    };
    owner.timer_probe(|consumed| {
        let result = unsafe { native(handle, 0) };
        if result == 0 && !timer.manual {
            consumed(timer.key());
        }
        result
    })
}

fn probe_timers(timers: &[Option<Arc<Timer>>], all: bool, probe: impl FnOnce() -> u32) -> u32 {
    let Some(owner) = timers
        .iter()
        .flatten()
        .find_map(|timer| timer.owner.upgrade())
    else {
        return probe();
    };
    owner.timer_probe(|consumed| {
        let result = probe();
        if result < timers.len() as u32 {
            for (index, timer) in timers.iter().enumerate() {
                if (all || index == result as usize)
                    && let Some(timer) = timer
                    && !timer.manual
                {
                    consumed(timer.key());
                }
            }
        }
        result
    })
}

impl Timer {
    fn key(&self) -> usize {
        std::ptr::from_ref(self) as usize
    }

    fn notify_groups(&self, wake_det: bool) {
        let groups: Vec<_> = {
            let mut state = self.state.lock().unwrap();
            state.groups.retain(|group| group.strong_count() != 0);
            state.groups.iter().filter_map(Weak::upgrade).collect()
        };
        if let Some(owner) = self.owner.upgrade() {
            for group in groups {
                let address = std::ptr::from_ref(&group.0).cast();
                if !wake_det {
                    owner.queue_timer_word_wake(address as usize, usize::MAX, group.clone());
                }
                owner.signal_timer_waiters(address as usize, group.clone(), || unsafe {
                    group.0.fetch_add(1, Ordering::Release);
                    original::<unsafe extern "system" fn(*const c_void)>(
                        &super::WAKE_BY_ADDRESS_ALL,
                    )(address);
                    usize::MAX
                });
                if wake_det {
                    owner.wake_timer_waiters(address as usize);
                }
            }
        }
    }

    fn cancel(&self, close: bool) {
        let key = {
            let mut state = self.state.lock().unwrap();
            state.generation += 1;
            state.deadline = None;
            state.period = None;
            state.closed |= close;
            state.wake.take()
        };
        if let Some(owner) = self.owner.upgrade() {
            if let Some(key) = key {
                owner.cancel_timer_wake(key);
            }
            owner.wake_timer_waiters(self.key());
        }
        self.notify_groups(true);
    }

    fn arm(self: &Arc<Self>, deadline: Duration, generation: u64, foreign: bool) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        let wake = owner.register_timer_wake(
            deadline,
            Waker::from(Arc::new(TimerWake {
                timer: Arc::downgrade(self),
                generation,
            })),
            foreign,
        );
        let mut state = self.state.lock().unwrap();
        if state.generation == generation && !state.closed && state.deadline == Some(deadline) {
            state.wake = wake;
        } else if let Some(key) = wake {
            drop(state);
            owner.cancel_timer_wake(key);
        }
    }

    fn signal(self: &Arc<Self>, generation: u64) {
        let (key, next, foreign) = {
            let mut state = self.state.lock().unwrap();
            let Some(deadline) = state.deadline else {
                return;
            };
            if state.closed || state.generation != generation {
                return;
            }
            let owner = self.owner.upgrade();
            if owner
                .as_ref()
                .is_some_and(|owner| !owner.timer_due(deadline))
            {
                return;
            }
            let Some(&handle) = state.handles.first() else {
                return;
            };
            if let Some(owner) = &owner {
                owner.signal_timer_waiters(self.key(), self.clone(), || {
                    signal_event(handle as HANDLE, self.manual)
                });
            } else {
                unsafe { SetEvent(handle as HANDLE) };
            }
            let now = owner
                .as_ref()
                .and_then(Domain::timer_now)
                .unwrap_or(deadline);
            let next = state.period.and_then(|period| {
                let steps = now.saturating_sub(deadline).as_nanos() / period.as_nanos() + 1;
                let nanos = deadline
                    .as_nanos()
                    .saturating_add(period.as_nanos().saturating_mul(steps));
                (nanos <= u64::MAX as u128).then(|| Duration::from_nanos(nanos as u64))
            });
            state.deadline = next;
            (state.wake.take(), next, state.foreign)
        };
        self.notify_groups(false);
        if let Some(owner) = self.owner.upgrade() {
            if let Some(key) = key {
                owner.cancel_timer_wake(key);
            }
            if let Some(next) = next {
                self.arm(next, generation, foreign);
            }
        }
    }
}

struct TimerWake {
    timer: Weak<Timer>,
    generation: u64,
}

impl Wake for TimerWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }
    fn wake_by_ref(self: &Arc<Self>) {
        let _pass = Passthrough::enter();
        if let Some(timer) = self.timer.upgrade() {
            timer.signal(self.generation);
        }
    }
}

pub(super) fn hooks() -> Vec<Hook> {
    vec![
        hook!("CreateWaitableTimerExW", "kernel32.dll", create, CREATE),
        hook!(
            "CreateWaitableTimerExA",
            "kernel32.dll",
            create_ex_a,
            CREATE_EX_A
        ),
        hook!("CreateWaitableTimerW", "kernel32.dll", create_w, CREATE_W),
        hook!("CreateWaitableTimerA", "kernel32.dll", create_a, CREATE_A),
        hook!("SetWaitableTimer", "kernel32.dll", set, SET),
        hook!("CancelWaitableTimer", "kernel32.dll", cancel, CANCEL),
        hook!("CloseHandle", "kernel32.dll", close, CLOSE),
        hook!("SetWaitableTimerEx", "kernel32.dll", set_ex, SET_EX),
        hook!("DuplicateHandle", "kernel32.dll", duplicate, DUPLICATE),
        hook!(
            "WaitForMultipleObjects",
            "kernel32.dll",
            wait_many,
            WAIT_MANY
        ),
        hook!(
            "WaitForMultipleObjectsEx",
            "kernel32.dll",
            wait_many_ex,
            WAIT_MANY_EX
        ),
        hook!("WaitForSingleObjectEx", "kernel32.dll", wait_ex, WAIT_EX),
    ]
}

unsafe extern "system" fn create(
    attributes: *const c_void,
    name: *const u16,
    flags: u32,
    access: u32,
) -> HANDLE {
    if let Some(handle) = create_model(attributes, !name.is_null(), flags, access) {
        return handle;
    }
    unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const u16, u32, u32) -> HANDLE>(
            &CREATE,
        )(attributes, name, flags, access)
    }
}

unsafe extern "system" fn create_ex_a(
    attributes: *const c_void,
    name: *const u8,
    flags: u32,
    access: u32,
) -> HANDLE {
    if let Some(handle) = create_model(attributes, !name.is_null(), flags, access) {
        return handle;
    }
    unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const u8, u32, u32) -> HANDLE>(
            &CREATE_EX_A,
        )(attributes, name, flags, access)
    }
}

unsafe extern "system" fn create_w(
    attributes: *const c_void,
    manual: i32,
    name: *const u16,
) -> HANDLE {
    if let Some(handle) = create_model(
        attributes,
        !name.is_null(),
        u32::from(manual != 0),
        TIMER_ALL_ACCESS,
    ) {
        return handle;
    }
    unsafe {
        original::<unsafe extern "system" fn(*const c_void, i32, *const u16) -> HANDLE>(&CREATE_W)(
            attributes, manual, name,
        )
    }
}

unsafe extern "system" fn create_a(
    attributes: *const c_void,
    manual: i32,
    name: *const u8,
) -> HANDLE {
    if let Some(handle) = create_model(
        attributes,
        !name.is_null(),
        u32::from(manual != 0),
        TIMER_ALL_ACCESS,
    ) {
        return handle;
    }
    unsafe {
        original::<unsafe extern "system" fn(*const c_void, i32, *const u8) -> HANDLE>(&CREATE_A)(
            attributes, manual, name,
        )
    }
}

fn create_model(attributes: *const c_void, named: bool, flags: u32, access: u32) -> Option<HANDLE> {
    let managed = domain::virtual_waits();
    let clock = managed.then(domain::virtual_now).flatten();
    if !managed || (clock.is_none() && domain::now(crate::ClockKind::Monotonic).is_none()) {
        return None;
    }
    if clock.is_none() || !domain::supports_timer_wakes() {
        unsupported();
        return Some(std::ptr::null_mut());
    }
    if named || !attributes.is_null() {
        unsupported();
        return Some(std::ptr::null_mut());
    }
    if flags & !3 != 0 {
        unsafe { SetLastError(ERROR_INVALID_PARAMETER) };
        return Some(std::ptr::null_mut());
    }
    let owner = Domain::current().unwrap().downgrade();
    let _pass = Passthrough::enter();
    let handle = unsafe { CreateEventExW(std::ptr::null(), std::ptr::null(), flags & 1, access) };
    if !handle.is_null() {
        table().lock().unwrap().insert(
            handle as usize,
            Arc::new(Timer {
                manual: flags & 1 != 0,
                owner,
                state: Mutex::new(TimerState {
                    handles: BTreeSet::from([handle as usize]),
                    ..TimerState::default()
                }),
            }),
        );
    }
    Some(handle)
}

type Apc = Option<unsafe extern "system" fn(*const c_void, u32, u32)>;

unsafe extern "system" fn set(
    handle: HANDLE,
    due: *const i64,
    period: i32,
    callback: Apc,
    argument: *const c_void,
    resume: i32,
) -> i32 {
    let Some(timer) = lookup(handle) else {
        return unsafe {
            original::<
                unsafe extern "system" fn(HANDLE, *const i64, i32, Apc, *const c_void, i32) -> i32,
            >(&SET)(handle, due, period, callback, argument, resume)
        };
    };
    if due.is_null() || period < 0 {
        unsafe { SetLastError(ERROR_INVALID_PARAMETER) };
        return 0;
    }
    let due = unsafe { due.read() };
    if callback.is_some()
        || resume != 0
        || !domain::virtual_waits()
        || Domain::current().is_none_or(|owner| owner.downgrade().key() != timer.owner.key())
    {
        return unsupported();
    }
    let _pass = Passthrough::enter();
    let ticks = due.unsigned_abs();
    let given = Duration::new(ticks / 10_000_000, ((ticks % 10_000_000) * 100) as u32);
    let after = if due > 0 {
        let filetime_offset = Duration::from_secs(11_644_473_600);
        given.saturating_sub(
            filetime_offset.saturating_add(domain::now(crate::ClockKind::Realtime).unwrap()),
        )
    } else {
        given
    };
    let deadline = domain::virtual_now()
        .unwrap()
        .saturating_add(after)
        .min(Duration::from_nanos(u64::MAX));
    let (generation, previous) = {
        let mut state = timer.state.lock().unwrap();
        if state.closed {
            unsafe { SetLastError(6) };
            return 0;
        }
        if unsafe { ResetEvent(handle) } == 0 {
            return 0;
        }
        let previous = state.wake.take();
        state.generation += 1;
        state.deadline = Some(deadline);
        state.period = (period > 0).then(|| Duration::from_millis(period as u64));
        state.foreign = crate::accounting::class() != crate::ThreadClass::Participant;
        (state.generation, previous)
    };
    if let (Some(key), Some(owner)) = (previous, timer.owner.upgrade()) {
        owner.cancel_timer_wake(key);
    }
    let foreign = timer.state.lock().unwrap().foreign;
    timer.arm(deadline, generation, foreign);
    timer.notify_groups(true);
    if domain::virtual_now().is_some_and(|now| now >= deadline) {
        timer.signal(generation);
    }

    1
}

unsafe extern "system" fn cancel(handle: HANDLE) -> i32 {
    let Some(timer) = lookup(handle) else {
        return unsafe { original::<unsafe extern "system" fn(HANDLE) -> i32>(&CANCEL)(handle) };
    };
    let _pass = Passthrough::enter();
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryObject(
            handle: HANDLE,
            class: u32,
            information: *mut c_void,
            size: u32,
            returned: *mut u32,
        ) -> i32;
        fn RtlNtStatusToDosError(status: i32) -> u32;
    }
    #[repr(align(8))]
    struct Basic([u32; 14]);
    let mut basic = Basic([0; 14]);
    let mut returned = 0;
    let status = unsafe {
        NtQueryObject(
            handle,
            0,
            basic.0.as_mut_ptr().cast(),
            size_of_val(&basic) as u32,
            &mut returned,
        )
    };
    if status < 0 {
        unsafe { SetLastError(RtlNtStatusToDosError(status)) };
        return 0;
    }
    if basic.0[1] & 2 == 0 {
        unsafe { SetLastError(5) };
        return 0;
    }
    timer.cancel(false);
    1
}

unsafe extern "system" fn close(handle: HANDLE) -> i32 {
    let native = unsafe { original::<unsafe extern "system" fn(*mut u8) -> i32>(&CLOSE) };
    if let Some(result) = unsafe { super::iocp::close(handle.cast(), native) } {
        return result;
    }
    let _pass = Passthrough::enter();
    let native = unsafe { original::<unsafe extern "system" fn(HANDLE) -> i32>(&CLOSE) };
    loop {
        let timer = lookup(handle);
        let mut state = timer.as_ref().map(|timer| timer.state.lock().unwrap());
        let mut timers = table().lock().unwrap();
        if !same_timer(timer.as_ref(), timers.get(&(handle as usize))) {
            drop(timers);
            drop(state);
            continue;
        }
        let result = unsafe { native(handle) };
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if result != 0 {
            timers.remove(&(handle as usize));
            if let Some(state) = &mut state {
                state.handles.remove(&(handle as usize));
            }
        }
        let last = state.as_ref().is_some_and(|state| state.handles.is_empty());
        drop(timers);
        drop(state);
        if last {
            timer.as_ref().unwrap().cancel(true);
        }
        unsafe { SetLastError(error) };
        return result;
    }
}

fn same_timer(before: Option<&Arc<Timer>>, current: Option<&Arc<Timer>>) -> bool {
    match (before, current) {
        (Some(before), Some(current)) => Arc::ptr_eq(before, current),
        (None, None) => true,
        _ => false,
    }
}

pub(super) unsafe fn close_native(handle: HANDLE) -> i32 {
    if CLOSE.load(Ordering::Acquire) == 0 {
        unsafe { windows_sys::Win32::Foundation::CloseHandle(handle) }
    } else {
        unsafe { original::<unsafe extern "system" fn(HANDLE) -> i32>(&CLOSE)(handle) }
    }
}

unsafe extern "system" fn set_ex(
    handle: HANDLE,
    due: *const i64,
    period: i32,
    callback: Apc,
    argument: *const c_void,
    context: *const c_void,
    delay: u32,
) -> i32 {
    if lookup(handle).is_none() {
        return unsafe {
            original::<
                unsafe extern "system" fn(
                    HANDLE,
                    *const i64,
                    i32,
                    Apc,
                    *const c_void,
                    *const c_void,
                    u32,
                ) -> i32,
            >(&SET_EX)(handle, due, period, callback, argument, context, delay)
        };
    }
    if !context.is_null() {
        return unsupported();
    }
    unsafe { set(handle, due, period, callback, argument, 0) }
}

unsafe extern "system" fn duplicate(
    source_process: HANDLE,
    source: HANDLE,
    target_process: HANDLE,
    target: *mut HANDLE,
    access: u32,
    inherit: i32,
    options: u32,
) -> i32 {
    let native = unsafe {
        original::<
            unsafe extern "system" fn(HANDLE, HANDLE, HANDLE, *mut HANDLE, u32, i32, u32) -> i32,
        >(&DUPLICATE)
    };
    if let Some(result) = unsafe {
        super::iocp::duplicate_boundary(
            source_process.cast(),
            source.cast(),
            options,
            original::<unsafe extern "system" fn(*mut u8) -> i32>(&CLOSE),
        )
    } {
        return result;
    }
    let _pass = Passthrough::enter();
    use windows_sys::Win32::System::Threading::{GetCurrentProcessId, GetProcessId};
    let current = unsafe { GetCurrentProcessId() };
    if unsafe { GetProcessId(source_process) } != current {
        return unsafe {
            native(
                source_process,
                source,
                target_process,
                target,
                access,
                inherit,
                options,
            )
        };
    }
    loop {
        let timer = lookup(source);
        let mut state = timer.as_ref().map(|timer| timer.state.lock().unwrap());
        let mut timers = table().lock().unwrap();
        if !same_timer(timer.as_ref(), timers.get(&(source as usize))) {
            drop(timers);
            drop(state);
            continue;
        }
        let foreign_target = timer.is_some() && !target_process.is_null() && {
            let target_pid = unsafe { GetProcessId(target_process) };
            target_pid != 0 && target_pid != current
        };
        let result = if foreign_target {
            if options & 1 != 0 {
                unsafe {
                    native(
                        source_process,
                        source,
                        std::ptr::null_mut(),
                        std::ptr::null_mut(),
                        0,
                        0,
                        1,
                    )
                };
            }
            unsupported()
        } else {
            unsafe {
                native(
                    source_process,
                    source,
                    target_process,
                    target,
                    access,
                    inherit,
                    options,
                )
            }
        };
        let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
        if let Some(state) = &mut state {
            if options & 1 != 0 {
                timers.remove(&(source as usize));
                state.handles.remove(&(source as usize));
            }
            if result != 0 && !target.is_null() && !target_process.is_null() {
                let handle = unsafe { *target };
                state.handles.insert(handle as usize);
                timers.insert(handle as usize, timer.as_ref().unwrap().clone());
            }
        }
        let last = state.as_ref().is_some_and(|state| state.handles.is_empty());
        drop(timers);
        drop(state);
        if last {
            timer.as_ref().unwrap().cancel(true);
        }
        unsafe { SetLastError(error) };
        return result;
    }
}

pub(super) fn wait(
    handle: HANDLE,
    timeout: u32,
    native: unsafe extern "system" fn(HANDLE, u32) -> u32,
) -> Option<u32> {
    if state::passthrough() {
        return None;
    }
    let timer = lookup(handle)?;
    let _label = crate::accounting::wait_label_on("sleep", timer.key());
    if !domain::virtual_waits()
        || Domain::current().is_none_or(|owner| owner.downgrade().key() != timer.owner.key())
    {
        unsupported();
        return Some(u32::MAX);
    }
    let timeout_deadline = (timeout != u32::MAX).then(|| {
        domain::virtual_now()
            .unwrap()
            .saturating_add(Duration::from_millis(timeout as u64))
    });
    loop {
        if domain::dormant() {
            domain::foreign_time_skip();
        }
        let (deadline, generation) = {
            let _pass = Passthrough::enter();
            let state = timer.state.lock().unwrap();
            (state.deadline, state.generation)
        };
        let now = domain::virtual_now().unwrap();
        if deadline.is_some_and(|at| now >= at) {
            let _pass = Passthrough::enter();
            timer.signal(generation);
        }
        let result = probe_timer(&timer, handle, native);
        if result != 258 {
            return Some(result);
        }
        if timeout_deadline.is_some_and(|at| now >= at) {
            return Some(258);
        }
        let until = match (deadline, timeout_deadline) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        if domain::counts_native_waits() && domain::det_active() {
            if deadline.is_some() && until == deadline {
                domain::det_block_registered_timer(crate::DetKey::Addr(timer.key()), until);
            } else {
                domain::det_block(crate::DetKey::Addr(timer.key()), until);
            }
        } else if let Some(until) = timeout_deadline {
            let outcome = domain::timed_native_wait_checked(
                until.saturating_sub(now),
                || {
                    let result = probe_timer(&timer, handle, native);
                    (result != 258).then_some(result)
                },
                |slice| {
                    let millis =
                        u32::try_from(slice.as_micros().div_ceil(1000)).unwrap_or(u32::MAX - 1);
                    let result = unsafe { native(handle, millis) };
                    (result != 258).then_some(result)
                },
                |result| *result != 258,
            );
            if let domain::TimedWait::Woken(result) = outcome {
                return Some(result);
            }
        } else {
            let result = domain::native_wait_at_checked(
                deadline,
                || {
                    let result = probe_timer(&timer, handle, native);
                    (result != 258).then_some(result)
                },
                || loop {
                    let result = unsafe { native(handle, 2) };
                    if result != 258 {
                        break result;
                    }
                    if domain::dormant() {
                        domain::foreign_time_skip();
                    }
                    let _pass = Passthrough::enter();
                    let (deadline, generation) = {
                        let state = timer.state.lock().unwrap();
                        (state.deadline, state.generation)
                    };
                    if deadline.is_some_and(|at| domain::virtual_now().unwrap() >= at) {
                        timer.signal(generation);
                    }
                },
                |result| *result != 258,
            );
            if result != 258 {
                return Some(result);
            }
        }
    }
}

unsafe extern "system" fn wait_ex(handle: HANDLE, timeout: u32, alertable: i32) -> u32 {
    if lookup(handle).is_some() && !state::passthrough() {
        if alertable != 0 {
            unsupported();
            return u32::MAX;
        }
        return unsafe { super::wait_for_single_object(handle, timeout) };
    }
    domain::observe("WaitForSingleObjectEx", None);
    unsafe {
        original::<unsafe extern "system" fn(HANDLE, u32, i32) -> u32>(&WAIT_EX)(
            handle, timeout, alertable,
        )
    }
}

unsafe extern "system" fn wait_many(
    count: u32,
    handles: *const HANDLE,
    all: i32,
    timeout: u32,
) -> u32 {
    let native = unsafe {
        original::<unsafe extern "system" fn(u32, *const HANDLE, i32, u32) -> u32>(&WAIT_MANY)
    };
    if state::passthrough() || count == 0 || count > 64 || handles.is_null() {
        return unsafe { native(count, handles, all, timeout) };
    }
    let handles_slice = unsafe { std::slice::from_raw_parts(handles, count as usize) };
    let timers: Vec<_> = handles_slice.iter().map(|&handle| lookup(handle)).collect();
    if timers.iter().all(Option::is_none) {
        domain::observe("WaitForMultipleObjects", None);
        return unsafe { native(count, handles, all, timeout) };
    }
    let result = probe_timers(&timers, all != 0, || unsafe {
        native(count, handles, all, 0)
    });
    if result != 258 || timeout == 0 {
        return result;
    }
    if !domain::virtual_waits() || timers.iter().any(|timer| timer.is_none()) {
        unsupported();
        return u32::MAX;
    }
    let owner = Domain::current().unwrap().downgrade().key();
    let timers: Vec<_> = timers.into_iter().map(Option::unwrap).collect();
    if timers.iter().any(|timer| timer.owner.key() != owner) {
        unsupported();
        return u32::MAX;
    }
    let group = Arc::new(WaitGroup::default());
    {
        let _pass = Passthrough::enter();
        for timer in &timers {
            timer
                .state
                .lock()
                .unwrap()
                .groups
                .push(Arc::downgrade(&group));
        }
    }
    let _registration = GroupRegistration {
        group: group.clone(),
        timers,
    };
    let until = (timeout != u32::MAX).then(|| {
        domain::virtual_now()
            .unwrap()
            .saturating_add(Duration::from_millis(timeout as u64))
    });
    loop {
        let expected = group.0.load(Ordering::Acquire);
        let result = Domain::current().unwrap().timer_probe(|consumed| {
            let result = unsafe { native(count, handles, all, 0) };
            if result < _registration.timers.len() as u32 {
                for (index, timer) in _registration.timers.iter().enumerate() {
                    if (all != 0 || index == result as usize) && !timer.manual {
                        consumed(timer.key());
                    }
                }
            }
            result
        });
        if result != 258 {
            return result;
        }
        let now = domain::virtual_now().unwrap();
        if until.is_some_and(|until| now >= until) {
            return 258;
        }
        let millis = until.map_or(u32::MAX, |until| {
            u32::try_from(until.saturating_sub(now).as_nanos().div_ceil(1_000_000))
                .unwrap_or(u32::MAX - 1)
        });
        let result = if domain::dormant() {
            wait_dormant_word(&group.0, expected, millis)
        } else {
            unsafe {
                super::wait_on_address(
                    std::ptr::from_ref(&group.0).cast(),
                    std::ptr::from_ref(&expected).cast(),
                    4,
                    millis,
                )
            }
        };
        if result == 0 && unsafe { windows_sys::Win32::Foundation::GetLastError() } != 1460 {
            return u32::MAX;
        }
    }
}

fn wait_dormant_word(word: &AtomicU32, expected: u32, timeout: u32) -> i32 {
    let address = std::ptr::from_ref(word).cast();
    let _label = crate::accounting::wait_label_on("waitable timers", address as usize);
    let wait = unsafe {
        original::<unsafe extern "system" fn(*const c_void, *const c_void, usize, u32) -> i32>(
            &super::WAIT_ON_ADDRESS,
        )
    };
    let preflight = || (word.load(Ordering::Acquire) != expected).then_some(1);
    let attempt = || {
        domain::foreign_time_skip();
        unsafe { wait(address, std::ptr::from_ref(&expected).cast(), 4, 2) }
    };
    if timeout == u32::MAX {
        domain::native_wait_at_checked(
            None,
            preflight,
            || loop {
                let result = attempt();
                if result != 0 || unsafe { windows_sys::Win32::Foundation::GetLastError() } != 1460
                {
                    break result;
                }
            },
            |result| *result != 0,
        )
    } else {
        match domain::timed_native_wait_checked(
            Duration::from_millis(timeout as u64),
            preflight,
            |_| {
                let result = attempt();
                (result != 0 || unsafe { windows_sys::Win32::Foundation::GetLastError() } != 1460)
                    .then_some(result)
            },
            |result| *result != 0,
        ) {
            domain::TimedWait::Woken(result) => result,
            domain::TimedWait::TimedOut => {
                unsafe { SetLastError(1460) };
                0
            }
        }
    }
}

unsafe extern "system" fn wait_many_ex(
    count: u32,
    handles: *const HANDLE,
    all: i32,
    timeout: u32,
    alertable: i32,
) -> u32 {
    if state::passthrough() || count == 0 || count > 64 || handles.is_null() {
        return unsafe {
            original::<unsafe extern "system" fn(u32, *const HANDLE, i32, u32, i32) -> u32>(
                &WAIT_MANY_EX,
            )(count, handles, all, timeout, alertable)
        };
    }
    let tracked = unsafe { std::slice::from_raw_parts(handles, count as usize) }
        .iter()
        .any(|&handle| lookup(handle).is_some());
    if !tracked {
        domain::observe("WaitForMultipleObjectsEx", None);
        return unsafe {
            original::<unsafe extern "system" fn(u32, *const HANDLE, i32, u32, i32) -> u32>(
                &WAIT_MANY_EX,
            )(count, handles, all, timeout, alertable)
        };
    }
    if alertable != 0 {
        unsupported();
        return u32::MAX;
    }
    unsafe { wait_many(count, handles, all, timeout) }
}
