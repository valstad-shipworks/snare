//! The clock, sleep, entropy and thread-id calls reached through `syscall(2)` are modelled as
//! their libc wrappers are: getrandom 0.2 (and so rand 0.8's `thread_rng`) fills buffers with
//! `syscall(SYS_getrandom, ..)`, and other code reads clocks the same way. The results follow
//! the wrapper's convention, `-1` with errno on failure (man 2 syscall).
#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use snare::{HostProfile, Sim};

const EPOCH: libc::time_t = 1_700_000_000;

fn det(seed: u64) -> Sim {
    Sim::builder().deterministic().seed(seed).build()
}

fn raw_random() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let n = unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), 0) };
    assert_eq!(n, 16);
    buf
}

fn wrapper_random() -> [u8; 16] {
    let mut buf = [0u8; 16];
    let n = unsafe { libc::getrandom(buf.as_mut_ptr().cast(), buf.len(), 0) };
    assert_eq!(n, 16);
    buf
}

#[test]
fn sys_getrandom_draws_the_seeded_stream() {
    let raw = det(7).run(|| std::thread::spawn(raw_random).join().unwrap());
    let again = det(7).run(|| std::thread::spawn(raw_random).join().unwrap());
    let wrapper = det(7).run(|| std::thread::spawn(wrapper_random).join().unwrap());
    assert_eq!(raw, again);
    assert_eq!(raw, wrapper);
    let probe = det(7).run(|| unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            std::ptr::null_mut::<u8>(),
            0usize,
            libc::GRND_NONBLOCK,
        )
    });
    assert_eq!(probe, 0, "getrandom 0.2's availability probe");
}

#[test]
fn sys_clock_gettime_and_gettimeofday_read_the_virtual_clock() {
    let (raw, wrapped, tv, mono) = Sim::builder().fixed_epoch().build().run(|| unsafe {
        let mut raw: libc::timespec = std::mem::zeroed();
        assert_eq!(
            libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut raw),
            0
        );
        let mut wrapped: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut wrapped);
        let mut tv: libc::timeval = std::mem::zeroed();
        assert_eq!(
            libc::syscall(
                libc::SYS_gettimeofday,
                &mut tv,
                std::ptr::null_mut::<libc::c_void>()
            ),
            0
        );
        let mut mono: libc::timespec = std::mem::zeroed();
        libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_MONOTONIC, &mut mono);
        (raw.tv_sec, wrapped.tv_sec, tv.tv_sec, mono.tv_sec)
    });
    assert_eq!((raw, wrapped, tv), (EPOCH, EPOCH, EPOCH));
    assert!(mono < 5, "monotonic starts near zero, got {mono}");
}

#[cfg(target_arch = "x86_64")]
#[test]
fn sys_time_reads_the_virtual_clock() {
    let (r, stored) = Sim::builder().fixed_epoch().build().run(|| {
        let mut stored: libc::time_t = 0;
        (
            unsafe { libc::syscall(libc::SYS_time, &mut stored) },
            stored,
        )
    });
    assert_eq!((r, stored), (EPOCH, EPOCH));
}

#[test]
fn raw_sleeps_wait_on_the_virtual_clock() {
    let real = Instant::now();
    let slept = Sim::builder().fixed_epoch().build().run(|| {
        let start = Instant::now();
        let request = libc::timespec {
            tv_sec: 30,
            tv_nsec: 0,
        };
        let mut left = libc::timespec {
            tv_sec: 9,
            tv_nsec: 9,
        };
        assert_eq!(
            unsafe { libc::syscall(libc::SYS_nanosleep, &request, &mut left) },
            0
        );
        assert_eq!((left.tv_sec, left.tv_nsec), (0, 0));
        let mut now: libc::timespec = unsafe { std::mem::zeroed() };
        unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
        let deadline = libc::timespec {
            tv_sec: now.tv_sec + 60,
            tv_nsec: now.tv_nsec,
        };
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_clock_nanosleep,
                    libc::CLOCK_MONOTONIC,
                    libc::TIMER_ABSTIME,
                    &deadline,
                    std::ptr::null_mut::<libc::timespec>(),
                )
            },
            0
        );
        start.elapsed()
    });
    assert!(slept >= Duration::from_secs(90), "virtual {slept:?}");
    assert!(real.elapsed() < Duration::from_secs(10));
}

#[test]
fn sys_gettid_is_the_hosts_thread_id() {
    let host = HostProfile::new().build();
    let (raw, wrapped) = Sim::builder()
        .host(host)
        .fixed_epoch()
        .build()
        .run(|| unsafe {
            (
                libc::syscall(libc::SYS_gettid) as libc::pid_t,
                libc::gettid(),
            )
        });
    assert_eq!(raw, wrapped);
}

#[test]
fn outside_a_sim_the_kernel_answers() {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    unsafe { libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut ts) };
    assert!(ts.tv_sec > EPOCH + 86_400 * 365);
    assert_eq!(unsafe { libc::syscall(libc::SYS_sched_yield) }, 0);
}
