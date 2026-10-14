#![cfg(windows)]

//! A `WinHost`'s processors against the machine the tests run on: `GetSystemInfo`, the processor
//! and group counts, `GetLogicalProcessorInformation(Ex)`, the process affinity mask, the NUMA
//! node masks and `CallNtPowerInformation(ProcessorInformation)`. Each probe runs for real, then
//! in a sim built with the machine's processor count and threads per core, and the two must
//! agree; then sims of other shapes are checked on their own, including what
//! `available_parallelism`, tokio and rayon size themselves by.
//!
//! The sim has one package and one die. On a machine with several (the Parallels VM has one
//! package per processor), package and die records and the sizes that count them are left out
//! of the comparison.

use std::ffi::c_void;

use snare::Sim;

type Handle = *mut c_void;

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetLastError() -> u32;
    fn SetLastError(error: u32);
    fn GetCurrentProcess() -> Handle;
    fn GetCurrentProcessId() -> u32;
    fn GetCurrentThread() -> Handle;
    fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
    fn CloseHandle(handle: Handle) -> i32;
    fn GetSystemInfo(info: *mut u8);
    fn GetNativeSystemInfo(info: *mut u8);
    fn GetActiveProcessorCount(group: u16) -> u32;
    fn GetMaximumProcessorCount(group: u16) -> u32;
    fn GetActiveProcessorGroupCount() -> u16;
    fn GetMaximumProcessorGroupCount() -> u16;
    fn GetLogicalProcessorInformation(info: *mut u8, len: *mut u32) -> i32;
    fn GetLogicalProcessorInformationEx(relationship: i32, info: *mut u8, len: *mut u32) -> i32;
    fn GetProcessAffinityMask(process: Handle, mask: *mut usize, system: *mut usize) -> i32;
    fn SetProcessAffinityMask(process: Handle, mask: usize) -> i32;
    fn SetThreadAffinityMask(thread: Handle, mask: usize) -> usize;
    fn GetNumaHighestNodeNumber(highest: *mut u32) -> i32;
    fn GetNumaNodeProcessorMask(node: u8, mask: *mut u64) -> i32;
    fn GetNumaNodeProcessorMaskEx(node: u16, affinity: *mut u8) -> i32;
    fn GetNumaNodeProcessorMask2(
        node: u16,
        affinities: *mut u8,
        count: u16,
        required: *mut u16,
    ) -> i32;
}

#[link(name = "powrprof")]
unsafe extern "system" {
    fn CallNtPowerInformation(
        level: i32,
        input: *const c_void,
        input_len: u32,
        output: *mut u8,
        output_len: u32,
    ) -> i32;
}

const ALL_PROCESSOR_GROUPS: u16 = 0xffff;
const RELATION_PROCESSOR_CORE: i32 = 0;
const RELATION_GROUP: i32 = 4;
const RELATION_PROCESSOR_PACKAGE: i32 = 3;
const RELATION_PROCESSOR_DIE: i32 = 5;
const RELATION_ALL: i32 = 0xffff;
const PROCESS_SET_INFORMATION: u32 = 0x0200;
const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
const PROCESSOR_INFORMATION: i32 = 11;
/// A last-error value no call under test sets, so a call that leaves it alone shows.
const UNTOUCHED: u32 = 0xdead;

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

/// Serializes the tests: the affinity probe changes the real process's mask.
fn host_state() -> std::sync::MutexGuard<'static, ()> {
    static HOST: std::sync::Mutex<()> = std::sync::Mutex::new(());
    HOST.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The `GetLogicalProcessorInformationEx(relationship)` records, each as its bytes.
fn ex_records(relationship: i32) -> Vec<Vec<u8>> {
    let mut len = 0u32;
    unsafe { GetLogicalProcessorInformationEx(relationship, std::ptr::null_mut(), &mut len) };
    let mut buf = vec![0u8; len as usize];
    assert_ne!(
        unsafe { GetLogicalProcessorInformationEx(relationship, buf.as_mut_ptr(), &mut len) },
        0
    );
    let mut records = Vec::new();
    let mut at = 0;
    while at < len as usize {
        let size = u32::from_ne_bytes(buf[at + 4..at + 8].try_into().unwrap()) as usize;
        records.push(buf[at..at + size].to_vec());
        at += size;
    }
    records
}

/// The machine's logical processors and how many of them its first core runs, read outside any
/// sim.
fn machine() -> (usize, usize) {
    let core = &ex_records(RELATION_PROCESSOR_CORE)[0];
    let mask = u64::from_ne_bytes(core[32..40].try_into().unwrap());
    (
        std::thread::available_parallelism().unwrap().get(),
        mask.count_ones() as usize,
    )
}

/// Whether the machine has one package, as the sim does.
fn one_package() -> bool {
    ex_records(RELATION_PROCESSOR_PACKAGE).len() == 1
}

fn like_the_machine() -> Sim {
    let (cpus, threads_per_core) = machine();
    Sim::builder()
        .cpus(cpus)
        .threads_per_core(threads_per_core)
        .build()
}

/// The counts, `SYSTEM_INFO`, the process affinity mask and the NUMA masks, with the last error
/// each call leaves.
fn count_probe() -> Vec<String> {
    let mut out = Vec::new();
    for (name, call) in [
        (
            "GetSystemInfo",
            GetSystemInfo as unsafe extern "system" fn(*mut u8),
        ),
        ("GetNativeSystemInfo", GetNativeSystemInfo),
    ] {
        let mut info = [0xccu8; 48];
        unsafe { SetLastError(UNTOUCHED) };
        unsafe { call(info.as_mut_ptr()) };
        out.push(format!("{name}: {info:02x?} {}", last_error()));
    }
    for group in [ALL_PROCESSOR_GROUPS, 0, 1, 2, 0xfffe, 0x7fff] {
        unsafe { SetLastError(UNTOUCHED) };
        let active = unsafe { GetActiveProcessorCount(group) };
        let active_error = last_error();
        unsafe { SetLastError(UNTOUCHED) };
        let maximum = unsafe { GetMaximumProcessorCount(group) };
        out.push(format!(
            "group {group:#x}: active {active} {active_error}, maximum {maximum} {}",
            last_error()
        ));
    }
    unsafe { SetLastError(UNTOUCHED) };
    let active = unsafe { GetActiveProcessorGroupCount() };
    let active_error = last_error();
    unsafe { SetLastError(UNTOUCHED) };
    let maximum = unsafe { GetMaximumProcessorGroupCount() };
    out.push(format!(
        "groups: active {active} {active_error}, maximum {maximum} {}",
        last_error()
    ));
    let (mut process, mut system) = (0usize, 0usize);
    let r = unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut process, &mut system) };
    out.push(format!("affinity: {r} {process:#x} {system:#x}"));
    let mut highest = 0xccu32;
    unsafe { SetLastError(UNTOUCHED) };
    let r = unsafe { GetNumaHighestNodeNumber(&mut highest) };
    out.push(format!("highest node: {r} {highest} {}", last_error()));
    for node in [0u16, 1, 63, 64, 0xffff] {
        let mut mask = 0xccccu64;
        unsafe { SetLastError(UNTOUCHED) };
        let r = unsafe { GetNumaNodeProcessorMask(node as u8, &mut mask) };
        out.push(format!(
            "node {} mask: {r} {mask:#x} {}",
            node as u8,
            last_error()
        ));
        let mut affinity = [0xccu8; 16];
        unsafe { SetLastError(UNTOUCHED) };
        let r = unsafe { GetNumaNodeProcessorMaskEx(node, affinity.as_mut_ptr()) };
        out.push(format!(
            "node {node} ex: {r} {affinity:02x?} {}",
            last_error()
        ));
        for count in [2u16, 0] {
            let mut affinities = [0xccu8; 32];
            let mut required = 0xccu16;
            unsafe { SetLastError(UNTOUCHED) };
            let r = unsafe {
                GetNumaNodeProcessorMask2(node, affinities.as_mut_ptr(), count, &mut required)
            };
            out.push(format!(
                "node {node} mask2 room {count}: {r} {required} {affinities:02x?} {}",
                last_error()
            ));
        }
    }
    out.push(format!(
        "available_parallelism: {:?}",
        std::thread::available_parallelism()
    ));
    out
}

#[test]
fn counts_match_the_host() {
    let _host = host_state();
    let real = count_probe();
    let simulated = like_the_machine().run(count_probe);
    assert_eq!(simulated, real);
}

/// Each record of a `GetLogicalProcessorInformationEx` buffer, or of a
/// `GetLogicalProcessorInformation` one (`legacy`, whose 32-byte records carry their relationship
/// at byte 8 and four bytes of padding the call never writes).
fn split(buf: &[u8], legacy: bool) -> Vec<Vec<u8>> {
    let mut records = Vec::new();
    let mut at = 0;
    while at < buf.len() {
        let size = if legacy {
            32
        } else {
            u32::from_ne_bytes(buf[at + 4..at + 8].try_into().unwrap()) as usize
        };
        records.push(buf[at..at + size].to_vec());
        at += size;
    }
    records
}

fn relationship_of(record: &[u8], legacy: bool) -> i32 {
    let at = if legacy { 8 } else { 0 };
    i32::from_ne_bytes(record[at..at + 4].try_into().unwrap())
}

/// The records of `buf` by relationship, each relationship's in order; caches are sorted, since
/// where a machine lists a cache shared by several cores is its own. Without `packages`, package
/// and die records are dropped. Also returns how many bytes the dropped records took.
fn describe(buf: &[u8], legacy: bool, packages: bool) -> (String, usize) {
    let mut records = split(buf, legacy);
    if !packages {
        records.retain(|record| {
            let relationship = relationship_of(record, legacy);
            relationship != RELATION_PROCESSOR_PACKAGE && relationship != RELATION_PROCESSOR_DIE
        });
    }
    let dropped = buf.len() - records.iter().map(Vec::len).sum::<usize>();
    let mut by_relationship: Vec<(i32, Vec<String>)> = Vec::new();
    for record in &records {
        let relationship = relationship_of(record, legacy);
        let text = format!("{record:02x?}");
        match by_relationship.iter_mut().find(|(r, _)| *r == relationship) {
            Some((_, list)) => list.push(text),
            None => by_relationship.push((relationship, vec![text])),
        }
    }
    by_relationship.sort_by_key(|(relationship, _)| *relationship);
    for (relationship, list) in &mut by_relationship {
        if *relationship == 2 {
            list.sort();
        }
    }
    (format!("{by_relationship:?}"), dropped)
}

/// The buffer conventions and contents of `GetLogicalProcessorInformation` (`relationship`
/// `None`) or `GetLogicalProcessorInformationEx`.
fn information_probe(relationship: Option<i32>, packages: bool) -> Vec<String> {
    let legacy = relationship.is_none();
    let call = |info: *mut u8, len: *mut u32| unsafe {
        match relationship {
            None => GetLogicalProcessorInformation(info, len),
            Some(relationship) => GetLogicalProcessorInformationEx(relationship, info, len),
        }
    };
    let mut out = Vec::new();
    let mut need = 0u32;
    unsafe { SetLastError(UNTOUCHED) };
    let r = call(std::ptr::null_mut(), &mut need);
    let error = last_error();
    let mut full = vec![0xccu8; need as usize + 64];
    let mut len = need + 64;
    unsafe { SetLastError(UNTOUCHED) };
    let ok = call(full.as_mut_ptr(), &mut len);
    let ok_error = last_error();
    if ok == 0 {
        out.push(format!(
            "asking: {r} {error} {need}; filling: {ok} {ok_error} {len}"
        ));
        return out;
    }
    let (records, dropped) = describe(&full[..len as usize], legacy, packages);
    out.push(format!(
        "filled: {ok} {ok_error} {} {records}",
        len as usize - dropped
    ));
    out.push(format!("asking: {r} {error} {}", need as usize - dropped));
    out.push(format!(
        "untouched past the records: {}",
        full[len as usize..].iter().all(|&b| b == 0xcc)
    ));
    let mut len = 7u32;
    unsafe { SetLastError(UNTOUCHED) };
    let r = call(std::ptr::null_mut(), &mut len);
    out.push(format!("no buffer, length 7: {r} {} {len}", last_error()));
    unsafe { SetLastError(UNTOUCHED) };
    let r = call(full.as_mut_ptr(), std::ptr::null_mut());
    out.push(format!("no length: {r} {}", last_error()));
    for room in [8u32, 32, 63] {
        let mut buf = vec![0xccu8; 64];
        let mut len = room;
        unsafe { SetLastError(UNTOUCHED) };
        let r = call(buf.as_mut_ptr(), &mut len);
        let written = if packages {
            format!("{buf:02x?}")
        } else {
            format!("{:?}", buf.iter().map(|&b| b != 0xcc).collect::<Vec<_>>())
        };
        out.push(format!(
            "room {room}: {r} {} {} {written}",
            last_error(),
            len as usize - dropped
        ));
    }
    out
}

#[test]
fn logical_processor_information_matches_the_host() {
    let _host = host_state();
    let packages = one_package();
    let mut probes: Vec<Option<i32>> = vec![None, Some(RELATION_ALL)];
    probes.extend([0, 1, 2, 4, 6, 7].map(Some));
    if packages {
        probes.extend([RELATION_PROCESSOR_PACKAGE, RELATION_PROCESSOR_DIE].map(Some));
    }
    let sim = like_the_machine();
    for relationship in probes {
        let real = information_probe(relationship, packages);
        let simulated = sim.run(|| information_probe(relationship, packages));
        assert_eq!(simulated, real, "relationship {relationship:?}");
    }
    for relationship in [8, 9, -1, 0xfffe, 0x10000] {
        let probe = || {
            let mut len = 4096u32;
            let mut buf = vec![0u8; 4096];
            unsafe { SetLastError(UNTOUCHED) };
            let r = unsafe {
                GetLogicalProcessorInformationEx(relationship, buf.as_mut_ptr(), &mut len)
            };
            (r, last_error(), len)
        };
        assert_eq!(sim.run(probe), probe(), "relationship {relationship}");
    }
}

/// `SetProcessAffinityMask` and `GetProcessAffinityMask`, and how the threads follow, with
/// handles of each access; the real side puts the process mask back.
fn affinity_probe() -> Vec<String> {
    std::thread::spawn(|| {
        let me = unsafe { GetCurrentProcess() };
        let get = |process: Handle| {
            let (mut mask, mut system) = (0usize, 0usize);
            unsafe { SetLastError(UNTOUCHED) };
            let r = unsafe { GetProcessAffinityMask(process, &mut mask, &mut system) };
            format!("get: {r} {} {mask:#x} {system:#x}", last_error())
        };
        let set = |process: Handle, mask: usize| {
            unsafe { SetLastError(UNTOUCHED) };
            let r = unsafe { SetProcessAffinityMask(process, mask) };
            format!("set {mask:#x}: {r} {}", last_error())
        };
        let thread = |mask: usize| {
            unsafe { SetLastError(UNTOUCHED) };
            let previous = unsafe { SetThreadAffinityMask(GetCurrentThread(), mask) };
            format!("thread {mask:#x}: {previous:#x} {}", last_error())
        };
        let (mut all, mut system) = (0usize, 0usize);
        unsafe { GetProcessAffinityMask(me, &mut all, &mut system) };
        let mut out = vec![get(me)];
        let pid = unsafe { GetCurrentProcessId() };
        for access in [PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SET_INFORMATION] {
            let handle = unsafe { OpenProcess(access, 0, pid) };
            out.push(format!("access {access:#x} {}", get(handle)));
            out.push(format!("access {access:#x} {}", set(handle, all)));
            unsafe { CloseHandle(handle) };
        }
        out.push(set(me, 0));
        if all != usize::MAX {
            out.push(set(me, all + 1));
            out.push(set(me, all | (all + 1)));
        }
        out.push(thread(0b10));
        out.push(set(me, 0b111));
        out.push(get(me));
        out.push(format!("after the process moved, {}", thread(0b1)));
        out.push(thread(0b1000));
        out.push(set(me, 0b11));
        out.push(format!("after it narrowed, {}", thread(0b1)));
        let mut info = [0u8; 48];
        unsafe { GetSystemInfo(info.as_mut_ptr()) };
        out.push(format!(
            "while narrowed: system info {:02x?}, {} active",
            &info[24..36],
            unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) }
        ));
        out.push(format!(
            "a new thread {}",
            std::thread::spawn(move || thread(0b1)).join().unwrap()
        ));
        out.push(set(me, all));
        out.push(get(me));
        out
    })
    .join()
    .unwrap()
}

#[test]
fn process_affinity_matches_the_host() {
    let _host = host_state();
    let (cpus, _) = machine();
    if cpus < 4 {
        return;
    }
    let real = affinity_probe();
    let simulated = like_the_machine().run(affinity_probe);
    assert_eq!(simulated, real);
}

/// `CallNtPowerInformation(ProcessorInformation)`'s statuses for each buffer, and for a full one,
/// the `Number` of each record and whether the room past them was left alone.
fn power_probe() -> Vec<String> {
    let cpus = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) } as usize;
    let mut out = Vec::new();
    let mut buf = vec![0xccu8; (cpus + 4) * 24];
    for (input, output, len) in [
        (false, false, 0),
        (false, false, cpus * 24),
        (false, true, 0),
        (false, true, cpus * 24 - 1),
        (true, true, cpus * 24),
        (false, true, cpus * 24 + 5),
    ] {
        let mut word = 0u64;
        let status = unsafe {
            CallNtPowerInformation(
                PROCESSOR_INFORMATION,
                if input {
                    std::ptr::from_mut(&mut word).cast()
                } else {
                    std::ptr::null()
                },
                if input { 8 } else { 0 },
                if output {
                    buf.as_mut_ptr()
                } else {
                    std::ptr::null_mut()
                },
                len as u32,
            )
        };
        out.push(format!(
            "input {input} output {output} length {len}: {status:#x}"
        ));
    }
    let numbers: Vec<u32> = buf[..cpus * 24]
        .as_chunks::<24>()
        .0
        .iter()
        .map(|record| u32::from_ne_bytes(record[..4].try_into().unwrap()))
        .collect();
    out.push(format!(
        "numbers {numbers:?}, untouched past them {}",
        buf[cpus * 24..].iter().all(|&b| b == 0xcc)
    ));
    out
}

#[test]
fn power_information_matches_the_host() {
    let real = power_probe();
    let simulated = like_the_machine().run(power_probe);
    assert_eq!(simulated, real);
}

/// Each of the sim's records of `relationship` as (relationship, mask, flags) for the processor
/// relationships, and the group record's counts and mask.
fn shape(relationship: i32) -> Vec<(i32, u64, u8)> {
    ex_records(relationship)
        .iter()
        .map(|record| {
            let relationship = i32::from_ne_bytes(record[..4].try_into().unwrap());
            let mask_at = match relationship {
                2 => 40,
                RELATION_GROUP => 72,
                _ => 32,
            };
            let flags = if relationship == RELATION_GROUP {
                record[33]
            } else {
                record[8]
            };
            let mask = u64::from_ne_bytes(record[mask_at..mask_at + 8].try_into().unwrap());
            (relationship, mask, flags)
        })
        .collect()
}

/// What a program counting processors sees: `available_parallelism`, `GetSystemInfo`'s count and
/// mask, `GetActiveProcessorCount`, the cores `num_cpus` counts from
/// `GetLogicalProcessorInformation`, and the process affinity mask.
fn counted() -> (usize, u32, u64, u32, usize, (usize, usize)) {
    let mut info = [0u8; 48];
    unsafe { GetSystemInfo(info.as_mut_ptr()) };
    let mut len = 0u32;
    unsafe { GetLogicalProcessorInformation(std::ptr::null_mut(), &mut len) };
    let mut buf = vec![0u8; len as usize];
    unsafe { GetLogicalProcessorInformation(buf.as_mut_ptr(), &mut len) };
    let cores = split(&buf, true)
        .iter()
        .filter(|record| relationship_of(record, true) == RELATION_PROCESSOR_CORE)
        .count();
    let (mut mask, mut system) = (0usize, 0usize);
    unsafe { GetProcessAffinityMask(GetCurrentProcess(), &mut mask, &mut system) };
    (
        std::thread::available_parallelism().unwrap().get(),
        u32::from_ne_bytes(info[32..36].try_into().unwrap()),
        u64::from_ne_bytes(info[24..32].try_into().unwrap()),
        unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) },
        cores,
        (mask, system),
    )
}

#[test]
fn the_profiles_processors_are_counted() {
    let six = Sim::builder().cpus(6).threads_per_core(2).build();
    assert_eq!(six.run(counted), (6, 6, 0x3f, 6, 3, (0x3f, 0x3f)));
    assert_eq!(
        six.run(|| shape(RELATION_PROCESSOR_CORE)),
        [(0, 0b11, 1), (0, 0b1100, 1), (0, 0b11_0000, 1)]
    );
    assert_eq!(
        six.run(|| shape(RELATION_GROUP)),
        [(RELATION_GROUP, 0x3f, 6)]
    );
    assert_eq!(
        six.run(|| shape(RELATION_PROCESSOR_PACKAGE)),
        [(RELATION_PROCESSOR_PACKAGE, 0x3f, 0)]
    );
    assert_eq!(
        six.run(|| shape(7)),
        [(7, 0b11, 0), (7, 0b1100, 0), (7, 0b11_0000, 0)]
    );
    assert_eq!(six.run(|| shape(1)), [(1, 0x3f, 0)]);
    let node = six.run(|| {
        let (mut mask, mut affinity, mut affinities, mut required) =
            (0u64, [0u8; 16], [0u8; 16], 0u16);
        unsafe {
            GetNumaNodeProcessorMask(0, &mut mask);
            GetNumaNodeProcessorMaskEx(0, affinity.as_mut_ptr());
            GetNumaNodeProcessorMask2(0, affinities.as_mut_ptr(), 1, &mut required);
        }
        let first = |bytes: [u8; 16]| u64::from_ne_bytes(bytes[..8].try_into().unwrap());
        (mask, first(affinity), first(affinities), required)
    });
    assert_eq!(node, (0x3f, 0x3f, 0x3f, 1));
    let one = Sim::builder().cpus(1).build();
    assert_eq!(one.run(counted), (1, 1, 1, 1, 1, (1, 1)));
    let full = Sim::builder().cpus(64).build();
    assert_eq!(
        full.run(counted),
        (64, 64, u64::MAX, 64, 64, (usize::MAX, usize::MAX))
    );
    assert_eq!(Sim::new().run(counted), (8, 8, 0xff, 8, 8, (0xff, 0xff)));
}

#[test]
fn caches_repeat_the_machines_per_core() {
    let (_, threads_per_core) = machine();
    let real = ex_records(2);
    let first_core = u64::from_ne_bytes(
        ex_records(RELATION_PROCESSOR_CORE)[0][32..40]
            .try_into()
            .unwrap(),
    );
    let per_core: Vec<&[u8]> = real
        .iter()
        .filter(|record| u64::from_ne_bytes(record[40..48].try_into().unwrap()) == first_core)
        .map(|record| &record[8..20])
        .collect();
    let sim = Sim::builder()
        .cpus(6)
        .threads_per_core(threads_per_core)
        .build();
    let simulated = sim.run(|| ex_records(2));
    for core in (0..6).step_by(threads_per_core) {
        let mask = ((1u64 << threads_per_core) - 1) << core;
        let descriptors: Vec<&[u8]> = simulated
            .iter()
            .filter(|record| u64::from_ne_bytes(record[40..48].try_into().unwrap()) == mask)
            .map(|record| &record[8..20])
            .collect();
        assert_eq!(descriptors, per_core, "core at {core}");
    }
}

#[test]
fn power_records_follow_the_profile() {
    let numbers = Sim::builder().cpus(6).build().run(|| {
        let mut buf = vec![0u8; 6 * 24];
        let status = unsafe {
            CallNtPowerInformation(
                PROCESSOR_INFORMATION,
                std::ptr::null(),
                0,
                buf.as_mut_ptr(),
                buf.len() as u32,
            )
        };
        assert_eq!(status, 0);
        buf.as_chunks::<24>()
            .0
            .iter()
            .map(|record| u32::from_ne_bytes(record[..4].try_into().unwrap()))
            .collect::<Vec<_>>()
    });
    assert_eq!(numbers, [0, 1, 2, 3, 4, 5]);
}

#[test]
fn runtimes_size_their_pools_by_the_profile() {
    let (workers, threads) = Sim::builder().cpus(3).build().run(|| {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        let workers = runtime.metrics().num_workers();
        drop(runtime);
        let pool = rayon::ThreadPoolBuilder::new().build().unwrap();
        (workers, pool.current_num_threads())
    });
    assert_eq!((workers, threads), (3, 3));
}
