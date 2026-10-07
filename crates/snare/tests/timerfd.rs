//! timerfd (man 2 timerfd_create) on the sim's clock, and the descriptor calls a program makes
//! through `syscall(2)` rather than their libc wrappers, which must reach the same model: rustix's
//! libc backend creates its eventfd with `syscall(SYS_eventfd2, ..)`, and polling, under
//! async-io, pairs it with a timerfd in one epoll set.
//!
//! Each sequence also runs on the host kernel (`*_os_truth`), pinning the model to Linux.

#![cfg(target_os = "linux")]

use std::time::{Duration, Instant};

use snare::Sim;

fn deterministic() -> Sim {
    Sim::builder()
        .deterministic()
        .stuck_after(Duration::from_secs(10))
        .build()
}

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn itimerspec(value: Duration, interval: Duration) -> libc::itimerspec {
    let ts = |d: Duration| libc::timespec {
        tv_sec: d.as_secs() as libc::time_t,
        tv_nsec: d.subsec_nanos() as libc::c_long,
    };
    libc::itimerspec {
        it_interval: ts(interval),
        it_value: ts(value),
    }
}

fn span(ts: libc::timespec) -> Duration {
    Duration::new(ts.tv_sec as u64, ts.tv_nsec as u32)
}

fn read_ticks(fd: i32) -> (isize, u64, i32) {
    let mut ticks = 0u64;
    let n = unsafe { libc::read(fd, (&mut ticks as *mut u64).cast(), 8) };
    (n, ticks, if n < 0 { errno() } else { 0 })
}

/// A nonblocking one-shot timer: EAGAIN before it expires, one tick after, EAGAIN again once
/// read, EINVAL for a short read, and a disarmed timer reads back zero.
fn one_shot() -> (i32, u64, i32, i32, bool) {
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK) };
    assert!(fd >= 0);
    let arm = itimerspec(Duration::from_millis(30), Duration::ZERO);
    assert_eq!(
        unsafe { libc::timerfd_settime(fd, 0, &arm, std::ptr::null_mut()) },
        0
    );
    let early = read_ticks(fd).2;
    std::thread::sleep(Duration::from_millis(40));
    let mut short = 0u32;
    let short = unsafe { libc::read(fd, (&mut short as *mut u32).cast(), 4) };
    let short = if short < 0 { errno() } else { 0 };
    let (_, ticks, _) = read_ticks(fd);
    let drained = read_ticks(fd).2;
    let mut current = itimerspec(Duration::ZERO, Duration::ZERO);
    assert_eq!(unsafe { libc::timerfd_gettime(fd, &mut current) }, 0);
    let disarmed = span(current.it_value).is_zero() && span(current.it_interval).is_zero();
    unsafe { libc::close(fd) };
    (early, ticks, short, drained, disarmed)
}

#[test]
fn a_one_shot_timer() {
    let expected = (libc::EAGAIN, 1, libc::EINVAL, libc::EAGAIN, true);
    assert_eq!(Sim::new().run(one_shot), expected);
    assert_eq!(deterministic().run(one_shot), expected);
}

#[test]
fn a_one_shot_timer_os_truth() {
    assert_eq!(
        one_shot(),
        (libc::EAGAIN, 1, libc::EINVAL, libc::EAGAIN, true)
    );
}

/// An interval timer read late counts every expiry since the last read; `old_value` returns the
/// setting replaced, and an absolute expiry already past fires at once.
fn intervals() -> (u64, Duration, u64) {
    let fd = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0) };
    let arm = itimerspec(Duration::from_millis(10), Duration::from_millis(10));
    unsafe { libc::timerfd_settime(fd, 0, &arm, std::ptr::null_mut()) };
    std::thread::sleep(Duration::from_millis(35));
    let (_, ticks, _) = read_ticks(fd);
    let mut now = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) };
    let past = itimerspec(
        span(now).saturating_sub(Duration::from_millis(1)),
        Duration::ZERO,
    );
    let mut old = itimerspec(Duration::ZERO, Duration::ZERO);
    unsafe { libc::timerfd_settime(fd, libc::TFD_TIMER_ABSTIME, &past, &mut old) };
    let (_, late, _) = read_ticks(fd);
    unsafe { libc::close(fd) };
    (ticks, span(old.it_interval), late)
}

#[test]
fn an_interval_timer() {
    let check = |(ticks, interval, late): (u64, Duration, u64)| {
        assert!((3..=4).contains(&ticks), "{ticks} expirations in 35 ms");
        assert_eq!(interval, Duration::from_millis(10));
        assert_eq!(late, 1);
    };
    check(Sim::new().run(intervals));
    check(deterministic().run(intervals));
}

#[test]
fn an_interval_timer_os_truth() {
    let (ticks, interval, late) = intervals();
    assert!(ticks >= 3, "{ticks} expirations in 35 ms");
    assert_eq!((interval, late), (Duration::from_millis(10), 1));
}

/// Bad flags and clocks are EINVAL; an alarm clock needs CAP_WAKE_ALARM.
fn bad_arguments() -> (i32, i32) {
    let flags = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, 0x4) };
    let flags = if flags < 0 { errno() } else { 0 };
    let clock = unsafe { libc::timerfd_create(1234, 0) };
    let clock = if clock < 0 { errno() } else { 0 };
    (flags, clock)
}

#[test]
fn bad_arguments_are_einval() {
    assert_eq!(Sim::new().run(bad_arguments), (libc::EINVAL, libc::EINVAL));
}

#[test]
fn bad_arguments_are_einval_os_truth() {
    assert_eq!(bad_arguments(), (libc::EINVAL, libc::EINVAL));
}

/// An epoll set holding an armed timerfd and an eventfd made through `syscall`, as polling's
/// Linux poller is: an infinite wait returns the timer at its expiry, and both registrations
/// still answer `EPOLL_CTL_MOD` afterwards.
fn epoll_with_timer() -> (i32, u64, Duration, i32, i32) {
    let start = Instant::now();
    let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let timer = unsafe {
        libc::timerfd_create(
            libc::CLOCK_MONOTONIC,
            libc::TFD_NONBLOCK | libc::TFD_CLOEXEC,
        )
    };
    let event = unsafe {
        libc::syscall(
            libc::SYS_eventfd2,
            0,
            libc::EFD_NONBLOCK | libc::EFD_CLOEXEC,
        )
    } as i32;
    assert!(ep >= 0 && timer >= 0 && event >= 0);
    for (fd, data) in [(timer, 1u64), (event, 2)] {
        let mut ev = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: data,
        };
        assert_eq!(
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) },
            0
        );
    }
    let arm = itimerspec(Duration::from_millis(30), Duration::ZERO);
    unsafe { libc::timerfd_settime(timer, 0, &arm, std::ptr::null_mut()) };
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 4, -1) };
    let waited = start.elapsed();
    let modify = |fd: i32| {
        let mut ev = libc::epoll_event {
            events: (libc::EPOLLIN | libc::EPOLLONESHOT) as u32,
            u64: 0,
        };
        let r = unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, fd, &mut ev) };
        if r < 0 { errno() } else { 0 }
    };
    let (timer_mod, event_mod) = (modify(timer), modify(event));
    for fd in [timer, event, ep] {
        unsafe { libc::close(fd) };
    }
    (n, out[0].u64, waited, timer_mod, event_mod)
}

fn check_epoll_with_timer((n, data, waited, timer_mod, event_mod): (i32, u64, Duration, i32, i32)) {
    assert_eq!((n, data), (1, 1));
    assert!(
        waited >= Duration::from_millis(30) && waited < Duration::from_secs(1),
        "the wait took {waited:?}"
    );
    assert_eq!((timer_mod, event_mod), (0, 0));
}

#[test]
fn an_epoll_wait_ends_at_a_timer_expiry() {
    check_epoll_with_timer(Sim::new().run(epoll_with_timer));
    check_epoll_with_timer(deterministic().run(epoll_with_timer));
}

#[test]
fn an_epoll_wait_ends_at_a_timer_expiry_os_truth() {
    check_epoll_with_timer(epoll_with_timer());
}

/// A real pipe registered in a simulated epoll set stays registered while it is open, as the
/// kernel keeps an epoll item until its file's last descriptor closes.
fn real_fd_registration() -> i32 {
    let mut pipe = [0; 2];
    assert_eq!(snare::real(|| unsafe { libc::pipe(pipe.as_mut_ptr()) }), 0);
    let ep = unsafe { libc::epoll_create1(0) };
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 9,
    };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, pipe[0], &mut ev) };
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 2];
    unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 2, 0) };
    let modified = unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_MOD, pipe[0], &mut ev) };
    let modified = if modified < 0 { errno() } else { 0 };
    unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_DEL, pipe[0], &mut ev) };
    snare::real(|| unsafe {
        libc::close(pipe[0]);
        libc::close(pipe[1]);
    });
    unsafe { libc::close(ep) };
    modified
}

#[test]
fn a_real_descriptor_stays_registered() {
    assert_eq!(Sim::new().run(real_fd_registration), 0);
}

#[test]
fn a_real_descriptor_stays_registered_os_truth() {
    assert_eq!(real_fd_registration(), 0);
}

/// A file whose driver has no poll (`/dev/null`, a regular file) cannot join an epoll set: Linux
/// refuses it with `EPERM`, which a reactor takes as its cue to do blocking I/O instead.
fn unpollable_registration() -> (i32, i32) {
    let null = snare::real(|| unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) });
    let file = std::env::current_exe().unwrap();
    let file = std::ffi::CString::new(file.into_os_string().into_encoded_bytes()).unwrap();
    let file = snare::real(|| unsafe { libc::open(file.as_ptr(), libc::O_RDONLY) });
    let ep = unsafe { libc::epoll_create1(0) };
    let mut ev = libc::epoll_event {
        events: libc::EPOLLIN as u32,
        u64: 1,
    };
    let mut add = |fd| {
        if unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut ev) } < 0 {
            errno()
        } else {
            0
        }
    };
    let refused = (add(null), add(file));
    unsafe { libc::close(ep) };
    snare::real(|| unsafe {
        libc::close(null);
        libc::close(file);
    });
    refused
}

#[test]
fn an_unpollable_file_is_eperm() {
    assert_eq!(
        Sim::new().run(unpollable_registration),
        (libc::EPERM, libc::EPERM)
    );
}

#[test]
fn an_unpollable_file_is_eperm_os_truth() {
    assert_eq!(unpollable_registration(), (libc::EPERM, libc::EPERM));
}
