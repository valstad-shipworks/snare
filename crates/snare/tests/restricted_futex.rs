#![cfg(target_os = "linux")]

use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};

use snare::Sim;

fn deny_process_reads(error: i32) {
    let mut filter = [
        libc::sock_filter {
            code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
            jt: 0,
            jf: 0,
            k: 0,
        },
        libc::sock_filter {
            code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
            jt: 0,
            jf: 1,
            k: libc::SYS_process_vm_readv as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ERRNO | error as u32,
        },
        libc::sock_filter {
            code: (libc::BPF_RET | libc::BPF_K) as u16,
            jt: 0,
            jf: 0,
            k: libc::SECCOMP_RET_ALLOW,
        },
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) },
        0
    );
    let word = 0u32;
    let mut copy = 0u32;
    let local = libc::iovec {
        iov_base: std::ptr::from_mut(&mut copy).cast(),
        iov_len: size_of::<u32>(),
    };
    let remote = libc::iovec {
        iov_base: std::ptr::from_ref(&word).cast_mut().cast(),
        iov_len: size_of::<u32>(),
    };
    assert_eq!(
        unsafe { libc::process_vm_readv(libc::getpid(), &local, 1, &remote, 1, 0) },
        -1
    );
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(error));
}

fn run_child(name: &str, error: i32, deterministic: bool) {
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([name, "--exact", "--nocapture"])
        .env("SNARE_FUTEX_DENIAL", error.to_string())
        .env("SNARE_FUTEX_DETERMINISTIC", deterministic.to_string())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while child.try_wait().unwrap().is_none() {
        if start.elapsed() >= Duration::from_secs(20) {
            child.kill().unwrap();
            let output = child.wait_with_output().unwrap();
            panic!(
                "child timed out: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "error={error} deterministic={deterministic}\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn child_configuration() -> Option<(i32, bool)> {
    Some((
        std::env::var("SNARE_FUTEX_DENIAL").ok()?.parse().unwrap(),
        std::env::var("SNARE_FUTEX_DETERMINISTIC")
            .unwrap()
            .parse()
            .unwrap(),
    ))
}

fn simulation(deterministic: bool) -> Sim {
    if deterministic {
        Sim::builder().deterministic().build()
    } else {
        Sim::new()
    }
}

#[test]
fn denied_process_reads_preserve_virtual_futex_timeouts() {
    for error in [libc::EPERM, libc::EACCES, libc::ENOSYS] {
        for deterministic in [false, true] {
            run_child("child_virtual_futex_timeouts", error, deterministic);
        }
    }
}

#[test]
fn child_virtual_futex_timeouts() {
    let Some((error, deterministic)) = child_configuration() else {
        return;
    };
    deny_process_reads(error);
    for private in [false, true] {
        for absolute in [false, true] {
            let sim = simulation(deterministic);
            sim.run(|| {
                let word = AtomicU32::new(0);
                let start = Instant::now();
                let mut timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 100_000_000,
                };
                let command = if absolute {
                    assert_eq!(
                        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut timeout) },
                        0
                    );
                    timeout.tv_nsec += 100_000_000;
                    timeout.tv_sec += timeout.tv_nsec / 1_000_000_000;
                    timeout.tv_nsec %= 1_000_000_000;
                    libc::FUTEX_WAIT_BITSET
                } else {
                    libc::FUTEX_WAIT
                } | if private { libc::FUTEX_PRIVATE_FLAG } else { 0 };
                let result = unsafe {
                    libc::syscall(
                        libc::SYS_futex,
                        &word,
                        command,
                        0u32,
                        &timeout,
                        0usize,
                        u32::MAX,
                    )
                };
                let error = std::io::Error::last_os_error().raw_os_error();
                assert_eq!((result, error), (-1, Some(libc::ETIMEDOUT)));
                let elapsed = start.elapsed();
                let timeout = Duration::from_millis(100);
                assert!(
                    (timeout..=timeout + Duration::from_nanos(1)).contains(&elapsed),
                    "private={private} absolute={absolute} elapsed={elapsed:?}"
                );
            });
        }
    }
    let sim = simulation(deterministic);
    sim.run(|| {
        let mutex = std::sync::Mutex::new(());
        let condvar = std::sync::Condvar::new();
        let start = Instant::now();
        let (_guard, result) = condvar
            .wait_timeout(mutex.lock().unwrap(), Duration::from_millis(100))
            .unwrap();
        assert!(result.timed_out());
        assert!(
            (Duration::from_millis(100)..=Duration::from_millis(100) + Duration::from_nanos(1))
                .contains(&start.elapsed())
        );
    });
}

#[test]
fn denied_process_reads_preserve_invalid_futex_arguments() {
    for error in [libc::EPERM, libc::EACCES, libc::ENOSYS] {
        for deterministic in [false, true] {
            run_child("child_invalid_futex_arguments", error, deterministic);
        }
    }
}

#[test]
fn child_invalid_futex_arguments() {
    let Some((error, deterministic)) = child_configuration() else {
        return;
    };
    deny_process_reads(error);
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let unreadable = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_NONE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(unreadable, libc::MAP_FAILED);
    let word = AtomicU32::new(1);
    let valid = std::ptr::from_ref(&word) as usize;
    let negative = libc::timespec {
        tv_sec: -1,
        tv_nsec: 0,
    };
    let invalid_nanos = libc::timespec {
        tv_sec: 0,
        tv_nsec: 1_000_000_000,
    };
    let timeout = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let probe = || {
        [
            (0, 0, u32::MAX),
            (valid + 1, 0, u32::MAX),
            (1, 0, u32::MAX),
            (unreadable as usize, 0, u32::MAX),
            (valid, 1, u32::MAX),
            (valid, unreadable as usize, u32::MAX),
            (valid, std::ptr::from_ref(&negative) as usize, u32::MAX),
            (valid, std::ptr::from_ref(&invalid_nanos) as usize, u32::MAX),
            (valid, std::ptr::from_ref(&timeout) as usize, 0),
            (valid, 0, u32::MAX),
        ]
        .map(|(address, timeout, mask)| {
            let result = unsafe {
                libc::syscall(
                    libc::SYS_futex,
                    address,
                    libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
                    0u32,
                    timeout,
                    0usize,
                    mask,
                )
            };
            (result, std::io::Error::last_os_error().raw_os_error())
        })
    };
    let native = snare::real(probe);
    assert_eq!(
        native.map(|(_, error)| error.unwrap()),
        [
            libc::EFAULT,
            libc::EINVAL,
            libc::EINVAL,
            libc::EFAULT,
            libc::EFAULT,
            libc::EFAULT,
            libc::EINVAL,
            libc::EINVAL,
            libc::EINVAL,
            libc::EAGAIN,
        ]
    );
    assert_eq!(simulation(deterministic).run(probe), native);
    assert_eq!(unsafe { libc::munmap(unreadable, page_size) }, 0);
}
