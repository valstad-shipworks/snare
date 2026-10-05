#![cfg(windows)]

//! The Windows scheduling extras against the machine the tests run on: MMCSS registrations
//! (`AvSetMmThreadCharacteristicsW` and friends), power throttling through
//! `SetProcessInformation`/`SetThreadInformation`, CPU sets and `SIO_CPU_AFFINITY`. Each probe
//! runs for real, then in a sim, and the two must agree; the real side puts back what it changed.

use std::ffi::c_void;

use snare::{PowerThrottling, Sim};

type Handle = *mut c_void;

#[link(name = "avrt")]
unsafe extern "system" {
    fn AvSetMmThreadCharacteristicsW(task: *const u16, index: *mut u32) -> Handle;
    fn AvSetMmThreadPriority(task: Handle, priority: i32) -> i32;
    fn AvRevertMmThreadCharacteristics(task: Handle) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn SetLastError(error: u32);
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentThread() -> Handle;
    fn GetCurrentThreadId() -> u32;
    fn SetProcessInformation(process: Handle, class: i32, info: *const c_void, size: u32) -> i32;
    fn GetProcessInformation(process: Handle, class: i32, info: *mut c_void, size: u32) -> i32;
    fn SetThreadInformation(thread: Handle, class: i32, info: *const c_void, size: u32) -> i32;
    fn GetThreadInformation(thread: Handle, class: i32, info: *mut c_void, size: u32) -> i32;
    fn GetSystemCpuSetInformation(
        info: *mut u8,
        len: u32,
        returned: *mut u32,
        process: Handle,
        flags: u32,
    ) -> i32;
    fn SetProcessDefaultCpuSets(process: Handle, ids: *const u32, count: u32) -> i32;
    fn GetProcessDefaultCpuSets(
        process: Handle,
        ids: *mut u32,
        count: u32,
        required: *mut u32,
    ) -> i32;
    fn GetLogicalProcessorInformationEx(relationship: i32, info: *mut u8, len: *mut u32) -> i32;
    fn SetThreadSelectedCpuSets(thread: Handle, ids: *const u32, count: u32) -> i32;
    fn GetThreadSelectedCpuSets(
        thread: Handle,
        ids: *mut u32,
        count: u32,
        required: *mut u32,
    ) -> i32;
}

#[link(name = "ws2_32")]
unsafe extern "system" {
    fn WSAStartup(version: u16, data: *mut u8) -> i32;
    fn socket(family: i32, kind: i32, protocol: i32) -> usize;
    fn bind(socket: usize, address: *const u8, length: i32) -> i32;
    fn closesocket(socket: usize) -> i32;
    fn WSAIoctl(
        socket: usize,
        code: u32,
        input: *const c_void,
        input_len: u32,
        output: *mut c_void,
        output_len: u32,
        returned: *mut u32,
        overlapped: *mut c_void,
        routine: *mut c_void,
    ) -> i32;
    fn WSAGetLastError() -> i32;
}

/// Serializes the tests: each changes process-wide state on the real side.
fn host_state() -> std::sync::MutexGuard<'static, ()> {
    static HOST: std::sync::Mutex<()> = std::sync::Mutex::new(());
    HOST.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain([0]).collect()
}

/// A `BOOL` call's outcome: `Ok(())`, or the last error it set.
fn outcome(result: i32) -> Result<(), u32> {
    if result != 0 {
        Ok(())
    } else {
        Err(unsafe { GetLastError() })
    }
}

/// Registers the calling thread with `task` at `index`: the index written back, or the error.
fn register(task: &str, index: u32) -> (Handle, Result<u32, u32>) {
    let mut index = index;
    unsafe { SetLastError(0) };
    let handle = unsafe { AvSetMmThreadCharacteristicsW(wide(task).as_ptr(), &mut index) };
    if handle.is_null() {
        (handle, Err(unsafe { GetLastError() }))
    } else {
        (handle, Ok(index))
    }
}

/// The MMCSS calls a real-time program makes, and their misuses, each on fresh threads.
fn mmcss_probe() -> Vec<String> {
    std::thread::spawn(|| {
        let mut out = Vec::new();
        let (task, first) = register("Pro Audio", 0);
        let index = first.unwrap();
        out.push(format!("register: ok {}", index != 0));
        out.push(format!("again: {:?}", register("Games", 0).1));
        out.push(format!("unknown name: {:?}", register("No Such Task", 0).1));
        out.push(format!(
            "unknown index: {:?}",
            register("Audio", 0x7fff_fff0).1
        ));
        for priority in [-3, -2, -1, 0, 1, 2, 3] {
            let r = outcome(unsafe { AvSetMmThreadPriority(task, priority) });
            out.push(format!("priority {priority}: {r:?}"));
        }
        let bogus = 0x1234usize as Handle;
        out.push(format!(
            "priority on a bogus handle: {:?}",
            outcome(unsafe { AvSetMmThreadPriority(bogus, 0) })
        ));
        let task_address = task as usize;
        let (joined, other) = std::thread::spawn(move || {
            let (handle, joined) = register("Pro Audio", index);
            let other = outcome(unsafe { AvSetMmThreadPriority(task_address as Handle, 1) });
            unsafe { AvRevertMmThreadCharacteristics(handle) };
            (joined.map(|i| i == index), other)
        })
        .join()
        .unwrap();
        out.push(format!("join the index: {joined:?}"));
        out.push(format!("priority from another thread: {other:?}"));
        out.push(format!(
            "revert: {:?}",
            outcome(unsafe { AvRevertMmThreadCharacteristics(task) })
        ));
        out.push(format!(
            "revert again: {:?}",
            outcome(unsafe { AvRevertMmThreadCharacteristics(task) })
        ));
        out.push(format!(
            "priority after revert: {:?}",
            outcome(unsafe { AvSetMmThreadPriority(task, 0) })
        ));
        out.push(format!(
            "register after revert: ok {}",
            register("Audio", 0).1.is_ok()
        ));
        out
    })
    .join()
    .unwrap()
}

#[test]
fn mmcss_matches_the_host() {
    let _host = host_state();
    let real = mmcss_probe();
    let simulated = Sim::new().run(mmcss_probe);
    assert_eq!(simulated, real);
}

#[test]
fn mmcss_registrations_read_back() {
    let sim = Sim::new();
    let (thread_id, handle) = sim.run(|| {
        let (handle, index) = register("Pro Audio", 0);
        assert_eq!(index, Ok(1));
        assert_ne!(unsafe { AvSetMmThreadPriority(handle, 2) }, 0);
        (unsafe { GetCurrentThreadId() }, handle as usize)
    });
    let tasks = sim.mmcss_tasks();
    assert_eq!(tasks.len(), 1);
    assert_eq!(
        (
            tasks[0].thread_id,
            tasks[0].task.as_str(),
            tasks[0].index,
            tasks[0].priority
        ),
        (thread_id, "Pro Audio", 1, 2)
    );
    sim.run(|| {
        assert_ne!(
            unsafe { AvRevertMmThreadCharacteristics(handle as Handle) },
            0
        )
    });
    assert!(sim.mmcss_tasks().is_empty());
}

const PROCESS_POWER_THROTTLING: i32 = 4;
const THREAD_POWER_THROTTLING: i32 = 3;

/// One power-throttling set, then a read back: (set outcome, read outcome, the state read).
fn throttle(thread: bool, state: [u32; 3], size: u32) -> String {
    unsafe { SetLastError(0) };
    let set = outcome(unsafe {
        if thread {
            SetThreadInformation(
                GetCurrentThread(),
                THREAD_POWER_THROTTLING,
                state.as_ptr().cast(),
                size,
            )
        } else {
            SetProcessInformation(
                GetCurrentProcess(),
                PROCESS_POWER_THROTTLING,
                state.as_ptr().cast(),
                size,
            )
        }
    });
    let mut read = [1u32, 0, 0];
    let got = outcome(unsafe {
        if thread {
            GetThreadInformation(
                GetCurrentThread(),
                THREAD_POWER_THROTTLING,
                read.as_mut_ptr().cast(),
                12,
            )
        } else {
            GetProcessInformation(
                GetCurrentProcess(),
                PROCESS_POWER_THROTTLING,
                read.as_mut_ptr().cast(),
                12,
            )
        }
    });
    format!("{thread} {state:?}/{size}: {set:?} {got:?} {read:?}")
}

fn power_throttling_probe() -> Vec<String> {
    std::thread::spawn(|| {
        let mut out = Vec::new();
        for thread in [false, true] {
            out.push(throttle(thread, [1, 0, 0], 12));
            for (state, size) in [
                ([1, 1, 1], 12),
                ([1, 1, 0], 12),
                ([1, 4, 4], 12),
                ([1, 5, 5], 12),
                ([1, 2, 2], 12),
                ([1, 8, 8], 12),
                ([1, 1, 3], 12),
                ([2, 1, 1], 12),
                ([0, 1, 1], 12),
                ([1, 1, 1], 8),
                ([1, 1, 1], 16),
            ] {
                out.push(throttle(thread, state, size));
            }
            out.push(throttle(thread, [1, 0, 0], 12));
        }
        let mut read = [2u32, 0, 0];
        out.push(format!(
            "read version 2: {:?}",
            outcome(unsafe {
                GetProcessInformation(
                    GetCurrentProcess(),
                    PROCESS_POWER_THROTTLING,
                    read.as_mut_ptr().cast(),
                    12,
                )
            })
        ));
        out
    })
    .join()
    .unwrap()
}

#[test]
fn power_throttling_matches_the_host() {
    let _host = host_state();
    let real = power_throttling_probe();
    let simulated = Sim::new().run(power_throttling_probe);
    assert_eq!(simulated, real);
}

#[test]
fn power_throttling_reads_back() {
    let sim = Sim::new();
    let thread_id = sim.run(|| {
        throttle(false, [1, 5, 4], 12);
        throttle(true, [1, 1, 1], 12);
        unsafe { GetCurrentThreadId() }
    });
    assert_eq!(
        sim.process_power_throttling(),
        PowerThrottling {
            control_mask: 5,
            state_mask: 4
        }
    );
    assert_eq!(
        sim.thread_power_throttling(thread_id),
        Some(PowerThrottling {
            control_mask: 1,
            state_mask: 1
        })
    );
}

/// The machine's CPU sets: each record's (size, type, id, group, logical processor, core).
fn cpu_sets() -> Vec<(u32, u32, u32, u16, u8, u8)> {
    let mut need = 0u32;
    unsafe { SetLastError(0) };
    let first = unsafe {
        GetSystemCpuSetInformation(std::ptr::null_mut(), 0, &mut need, GetCurrentProcess(), 0)
    };
    assert_eq!((first, unsafe { GetLastError() }), (0, 122));
    let mut buf = vec![0u8; need as usize];
    assert_ne!(
        unsafe {
            GetSystemCpuSetInformation(buf.as_mut_ptr(), need, &mut need, GetCurrentProcess(), 0)
        },
        0
    );
    let word = |at: usize| u32::from_ne_bytes(buf[at..at + 4].try_into().unwrap());
    let mut out = Vec::new();
    let mut at = 0;
    while at < need as usize {
        out.push((
            word(at),
            word(at + 4),
            word(at + 8),
            u16::from_ne_bytes([buf[at + 12], buf[at + 13]]),
            buf[at + 14],
            buf[at + 15],
        ));
        at += word(at) as usize;
    }
    out
}

/// How many logical processors the machine's first core runs, from its `RelationProcessorCore`
/// record's group mask
/// ([Microsoft Learn: GetLogicalProcessorInformationEx](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getlogicalprocessorinformationex)).
fn threads_per_core() -> usize {
    const RELATION_PROCESSOR_CORE: i32 = 0;
    let mut len = 0u32;
    unsafe {
        GetLogicalProcessorInformationEx(RELATION_PROCESSOR_CORE, std::ptr::null_mut(), &mut len)
    };
    let mut buf = vec![0u8; len as usize];
    assert_ne!(
        unsafe {
            GetLogicalProcessorInformationEx(RELATION_PROCESSOR_CORE, buf.as_mut_ptr(), &mut len)
        },
        0
    );
    // Relationship and Size, then PROCESSOR_RELATIONSHIP: Flags, EfficiencyClass, Reserved[20],
    // GroupCount, and the first GROUP_AFFINITY's Mask.
    let mask = usize::from_ne_bytes(buf[32..32 + size_of::<usize>()].try_into().unwrap());
    mask.count_ones() as usize
}

/// The CPU sets read back: (outcome, required, ids).
fn read_sets(thread: bool, room: u32) -> String {
    let mut ids = vec![0u32; room as usize];
    let mut required = 0u32;
    unsafe { SetLastError(0) };
    let r = outcome(unsafe {
        if thread {
            GetThreadSelectedCpuSets(GetCurrentThread(), ids.as_mut_ptr(), room, &mut required)
        } else {
            GetProcessDefaultCpuSets(GetCurrentProcess(), ids.as_mut_ptr(), room, &mut required)
        }
    });
    ids.truncate(required.min(room) as usize);
    format!("{r:?} {required} {ids:?}")
}

fn choose_sets(thread: bool, ids: &[u32]) -> Result<(), u32> {
    unsafe { SetLastError(0) };
    outcome(unsafe {
        if thread {
            SetThreadSelectedCpuSets(GetCurrentThread(), ids.as_ptr(), ids.len() as u32)
        } else {
            SetProcessDefaultCpuSets(GetCurrentProcess(), ids.as_ptr(), ids.len() as u32)
        }
    })
}

fn cpu_set_probe() -> Vec<String> {
    std::thread::spawn(|| {
        let sets = cpu_sets();
        let ids: Vec<u32> = sets.iter().map(|s| s.2).collect();
        let mut out = vec![format!("{sets:?}")];
        for thread in [false, true] {
            out.push(read_sets(thread, 8));
            out.push(format!("one: {:?}", choose_sets(thread, &ids[..1])));
            out.push(read_sets(thread, 8));
            out.push(read_sets(thread, 0));
            out.push(format!("unknown: {:?}", choose_sets(thread, &[0x999])));
            out.push(read_sets(thread, 8));
            out.push(format!(
                "reversed with a repeat: {:?}",
                choose_sets(thread, &[ids[1], ids[0], ids[1]])
            ));
            out.push(read_sets(thread, 8));
            out.push(read_sets(thread, 1));
            out.push(format!("clear: {:?}", choose_sets(thread, &[])));
            out.push(read_sets(thread, 8));
        }
        out
    })
    .join()
    .unwrap()
}

#[test]
fn cpu_sets_match_the_host() {
    let _host = host_state();
    let real = cpu_set_probe();
    let cpus = std::thread::available_parallelism().unwrap().get();
    let simulated = Sim::builder()
        .cpus(cpus)
        .threads_per_core(threads_per_core())
        .build()
        .run(cpu_set_probe);
    assert_eq!(simulated, real);
}

#[test]
fn cpu_sets_group_smt_siblings_into_cores() {
    let cores = |threads| {
        Sim::builder()
            .cpus(5)
            .threads_per_core(threads)
            .build()
            .run(|| cpu_sets().iter().map(|s| (s.4, s.5)).collect::<Vec<_>>())
    };
    assert_eq!(cores(1), [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4)]);
    assert_eq!(cores(2), [(0, 0), (1, 0), (2, 2), (3, 2), (4, 4)]);
}

#[test]
fn cpu_sets_read_back() {
    let sim = Sim::builder().cpus(4).build();
    let thread_id = sim.run(|| {
        choose_sets(false, &[0x103, 0x101]).unwrap();
        choose_sets(true, &[0x102]).unwrap();
        unsafe { GetCurrentThreadId() }
    });
    assert_eq!(sim.process_default_cpu_sets(), [0x101, 0x103]);
    assert_eq!(sim.thread_selected_cpu_sets(thread_id), [0x102]);
}

const SIO_CPU_AFFINITY: u32 = 0x9800_0015;

fn cpu_affinity(socket: usize, input: &[u8]) -> Result<(), i32> {
    let mut returned = 0u32;
    let r = unsafe {
        WSAIoctl(
            socket,
            SIO_CPU_AFFINITY,
            input.as_ptr().cast(),
            input.len() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if r == 0 {
        Ok(())
    } else {
        Err(unsafe { WSAGetLastError() })
    }
}

fn sio_cpu_affinity_probe() -> Vec<String> {
    let mut data = [0u8; 512];
    unsafe { WSAStartup(0x202, data.as_mut_ptr()) };
    let mut loopback = [0u8; 16];
    loopback[0] = 2;
    loopback[4] = 127;
    loopback[7] = 1;
    let mut out = Vec::new();
    for (kind, name) in [(2, "udp"), (1, "tcp")] {
        let s = unsafe { socket(2, kind, 0) };
        for input in [
            &0u16.to_ne_bytes()[..],
            &1u16.to_ne_bytes(),
            &999u16.to_ne_bytes(),
            &0u32.to_ne_bytes(),
            &[0u8],
            &[],
        ] {
            out.push(format!("{name} {input:?}: {:?}", cpu_affinity(s, input)));
        }
        assert_eq!(unsafe { bind(s, loopback.as_ptr(), 16) }, 0);
        out.push(format!(
            "{name} bound: {:?} {:?}",
            cpu_affinity(s, &0u16.to_ne_bytes()),
            cpu_affinity(s, &[0u8])
        ));
        unsafe { closesocket(s) };
    }
    out
}

#[test]
fn sio_cpu_affinity_matches_the_host() {
    let real = sio_cpu_affinity_probe();
    let simulated = Sim::new().run(sio_cpu_affinity_probe);
    assert_eq!(simulated, real);
}

#[test]
fn sio_cpu_affinity_reads_back() {
    let sim = Sim::new();
    sim.run(|| {
        use std::os::windows::io::FromRawSocket;
        let raw = unsafe { socket(2, 2, 0) };
        cpu_affinity(raw, &3u16.to_ne_bytes()).unwrap();
        let udp = unsafe { std::net::UdpSocket::from_raw_socket(raw as u64) };
        let id = snare::socket_id(&udp).unwrap();
        assert_eq!(sim.socket_cpu_affinity(id), Some(3));
    });
}

#[link(name = "winmm")]
unsafe extern "system" {
    fn timeBeginPeriod(period: u32) -> u32;
    fn timeEndPeriod(period: u32) -> u32;
}

#[test]
fn time_periods_read_back() {
    let sim = Sim::new();
    sim.run(|| unsafe {
        assert_eq!(timeBeginPeriod(4), 0);
        assert_eq!(timeBeginPeriod(1), 0);
        assert_eq!(timeBeginPeriod(1), 0);
    });
    assert_eq!(sim.time_periods(), [(1, 2), (4, 1)]);
    sim.run(|| unsafe {
        assert_eq!(timeEndPeriod(1), 0);
        assert_eq!(timeEndPeriod(4), 0);
    });
    assert_eq!(sim.time_periods(), [(1, 1)]);
}
