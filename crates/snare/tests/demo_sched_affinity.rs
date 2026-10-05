#![cfg(target_os = "linux")]

//! CPU-affinity coverage: `sched_setaffinity`/`sched_getaffinity` through the named wrappers and
//! the raw syscall, plus the boundary and error paths.
//!
//! man 2 sched_setaffinity: the affinity mask is a `cpu_set_t` built with the CPU_SET(3) macros;
//! `cpusetsize` is its size in bytes. EINVAL is returned when the mask selects no CPU that is
//! actually on the system, or when the supplied size is smaller than the kernel's `cpu_set_t`.

use snare::{HostProfile, Sim};

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

fn mask_of(cpus: &[usize]) -> libc::cpu_set_t {
    let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
    unsafe { libc::CPU_ZERO(&mut set) };
    for &c in cpus {
        unsafe { libc::CPU_SET(c, &mut set) };
    }
    set
}

fn set_bits(set: &libc::cpu_set_t, upto: usize) -> Vec<usize> {
    (0..upto)
        .filter(|&c| unsafe { libc::CPU_ISSET(c, set) })
        .collect()
}

const CPU_SET_LEN: usize = std::mem::size_of::<libc::cpu_set_t>();

#[test]
fn affinity_round_trips_through_the_raw_syscall() {
    let host = HostProfile::new().cpus(8).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() } as i64;
        let set = mask_of(&[1, 3, 6]);
        let rc = unsafe {
            libc::syscall(
                libc::SYS_sched_setaffinity,
                tid,
                CPU_SET_LEN,
                &set as *const libc::cpu_set_t,
            )
        };
        assert_eq!(rc, 0);

        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::syscall(
                libc::SYS_sched_getaffinity,
                tid,
                CPU_SET_LEN,
                &mut read as *mut libc::cpu_set_t,
            )
        };
        assert_eq!(rc, 0);
        assert_eq!(set_bits(&read, 8), vec![1, 3, 6]);
    });
}

#[test]
fn default_affinity_is_every_online_cpu() {
    // man 2 sched_getaffinity: with no explicit restriction the mask spans the online CPUs. A
    // freshly minted thread has not narrowed its affinity, so all of 0..cpus must read back set.
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(tid, CPU_SET_LEN, &mut read) },
            0
        );
        assert_eq!(set_bits(&read, 4), vec![0, 1, 2, 3]);
    });
}

#[test]
fn default_affinity_follows_a_sparse_online_set() {
    // /sys/devices/system/cpu/online may be sparse (e.g. some CPUs offline). getaffinity's
    // "all online CPUs" default must reflect exactly that set, not 0..cpu_count.
    let host = HostProfile::new().cpus(6).online([0, 2, 4]).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(tid, CPU_SET_LEN, &mut read) },
            0
        );
        assert_eq!(set_bits(&read, 6), vec![0, 2, 4]);
    });
}

#[test]
fn pinning_to_a_single_cpu() {
    let host = HostProfile::new().cpus(8).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let set = mask_of(&[3]);
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &set) },
            0
        );
        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(tid, CPU_SET_LEN, &mut read) },
            0
        );
        assert_eq!(set_bits(&read, 8), vec![3]);
        assert_eq!(unsafe { libc::CPU_COUNT(&read) }, 1);
    });
}

#[test]
fn out_of_range_bits_are_dropped_when_some_bit_is_valid() {
    // The kernel intersects the requested mask with the online CPUs; bits past the CPU count are
    // silently ignored as long as at least one valid CPU remains (only an all-invalid mask is
    // EINVAL). Here CPUs 9 and 30 do not exist, but CPU 1 does.
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let set = mask_of(&[1, 9, 30]);
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &set) },
            0
        );
        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(tid, CPU_SET_LEN, &mut read) },
            0
        );
        assert_eq!(set_bits(&read, 64), vec![1]);
    });
}

#[test]
fn mask_selecting_only_offline_cpus_is_einval() {
    // man 2 sched_setaffinity ERRORS: EINVAL when the mask contains no CPU currently on the system.
    let host = HostProfile::new().cpus(2).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let set = mask_of(&[7]);
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &set) },
            -1
        );
        assert_eq!(errno(), libc::EINVAL);
    });
}

#[test]
fn empty_mask_is_einval() {
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let set = mask_of(&[]);
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &set) },
            -1
        );
        assert_eq!(errno(), libc::EINVAL);
    });
}

#[test]
fn undersized_cpusetsize_is_einval() {
    // man 2 sched_setaffinity ERRORS: EINVAL when `cpusetsize` is smaller than the kernel's
    // internal cpu_set_t. A one-byte length cannot describe the mask.
    let host = HostProfile::new().cpus(4).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let set = mask_of(&[0]);
        assert_eq!(unsafe { libc::sched_setaffinity(tid, 1, &set) }, -1);
        assert_eq!(errno(), libc::EINVAL);

        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sched_getaffinity(tid, 1, &mut read) }, -1);
        assert_eq!(errno(), libc::EINVAL);
    });
}

#[test]
fn affinity_is_per_thread() {
    let host = HostProfile::new().cpus(8).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        let set = mask_of(&[0, 1]);
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &set) },
            0
        );

        let child = std::thread::spawn(|| {
            let ctid = unsafe { libc::gettid() };
            let cset = mask_of(&[4, 5, 6, 7]);
            assert_eq!(
                unsafe { libc::sched_setaffinity(ctid, CPU_SET_LEN, &cset) },
                0
            );
            let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sched_getaffinity(ctid, CPU_SET_LEN, &mut read) },
                0
            );
            set_bits(&read, 8)
        });
        assert_eq!(child.join().unwrap(), vec![4, 5, 6, 7]);

        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(tid, CPU_SET_LEN, &mut read) },
            0
        );
        assert_eq!(set_bits(&read, 8), vec![0, 1], "main thread unchanged");
    });
}

#[test]
fn rewriting_affinity_replaces_the_previous_mask() {
    let host = HostProfile::new().cpus(8).build();
    Sim::builder().host(host).build().run(|| {
        let tid = unsafe { libc::gettid() };
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &mask_of(&[0, 1, 2])) },
            0
        );
        assert_eq!(
            unsafe { libc::sched_setaffinity(tid, CPU_SET_LEN, &mask_of(&[5])) },
            0
        );
        let mut read: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sched_getaffinity(tid, CPU_SET_LEN, &mut read) },
            0
        );
        assert_eq!(set_bits(&read, 8), vec![5]);
    });
}
