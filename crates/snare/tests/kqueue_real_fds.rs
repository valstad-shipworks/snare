//! Real descriptors in a simulated kqueue: a pipe or socketpair the sim does not serve (made
//! before the sim, or through `snare::real`) registers with `EVFILT_READ`/`EVFILT_WRITE` and
//! reports the OS's readiness, as tokio's process-wide signal socketpair needs when a runtime is
//! built inside a sim after one was built outside it. A kqueue wait with a timeout still runs on
//! the sim clock.
//!
//! Each sequence also runs on the host kernel (`*_os_truth`), pinning the model to macOS.

#![cfg(target_os = "macos")]

use std::io::Write;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use snare::Sim;

fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap()
}

fn kev(ident: i32, filter: i16, flags: u16, udata: u64) -> libc::kevent {
    libc::kevent {
        ident: ident as usize,
        filter,
        flags,
        fflags: 0,
        data: 0,
        udata: udata as *mut libc::c_void,
    }
}

/// Applies `changes` with no room for events: 0, or the errno.
fn apply(kq: i32, changes: &[libc::kevent]) -> i32 {
    let n = unsafe {
        libc::kevent(
            kq,
            changes.as_ptr(),
            changes.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    if n < 0 { errno() } else { n }
}

/// A zero-timeout `kevent`: each event's `(udata, filter, flags, data)`, sorted.
fn take(kq: i32) -> Vec<(u64, i16, u16, i64)> {
    let mut out = [kev(0, 0, 0, 0); 8];
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 8, &zero) };
    assert!(n >= 0, "kevent: {}", std::io::Error::last_os_error());
    let mut got: Vec<_> = out[..n as usize]
        .iter()
        .map(|e| (e.udata as u64, e.filter, e.flags, e.data as i64))
        .collect();
    got.sort_unstable();
    got
}

fn real_pipe() -> [i32; 2] {
    let mut pipe = [0; 2];
    assert_eq!(snare::real(|| unsafe { libc::pipe(pipe.as_mut_ptr()) }), 0);
    pipe
}

fn real_write(fd: i32, bytes: &[u8]) {
    let n = snare::real(|| unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) });
    assert_eq!(n, bytes.len() as isize);
}

fn real_read(fd: i32, len: usize) {
    let mut buf = vec![0u8; len];
    let n = snare::real(|| unsafe { libc::read(fd, buf.as_mut_ptr().cast(), len) });
    assert_eq!(n, len as isize);
}

fn real_close(fds: &[i32]) {
    snare::real(|| {
        for &fd in fds {
            unsafe { libc::close(fd) };
        }
    });
}

type Event = (u64, i16, u16, i64);

#[derive(Debug, PartialEq)]
struct PipeReadiness {
    added: i32,
    idle: Vec<Event>,
    readable: Vec<Event>,
    again: Vec<Event>,
    deleted: (i32, i32),
    writable: Vec<Event>,
}

/// A real pipe's read end is reported readable with the bytes queued, level-triggered, and its
/// write end writable (`data` read as whether it has room); `EV_DELETE` removes the registration
/// and a second one is ENOENT.
fn pipe_readiness() -> PipeReadiness {
    let pipe = real_pipe();
    let kq = unsafe { libc::kqueue() };
    let added = apply(kq, &[kev(pipe[0], libc::EVFILT_READ, libc::EV_ADD, 9)]);
    let idle = take(kq);
    real_write(pipe[1], b"abc");
    let readable = take(kq);
    let again = take(kq);
    let deleted = (
        apply(kq, &[kev(pipe[0], libc::EVFILT_READ, libc::EV_DELETE, 0)]),
        apply(kq, &[kev(pipe[0], libc::EVFILT_READ, libc::EV_DELETE, 0)]),
    );
    apply(kq, &[kev(pipe[1], libc::EVFILT_WRITE, libc::EV_ADD, 4)]);
    let writable = take(kq)
        .into_iter()
        .map(|(udata, filter, flags, data)| (udata, filter, flags, i64::from(data > 0)))
        .collect();
    unsafe { libc::close(kq) };
    real_close(&pipe);
    PipeReadiness {
        added,
        idle,
        readable,
        again,
        deleted,
        writable,
    }
}

fn check_pipe_readiness(got: PipeReadiness) {
    let readable = vec![(9, libc::EVFILT_READ, libc::EV_ADD, 3)];
    assert_eq!(
        got,
        PipeReadiness {
            added: 0,
            idle: vec![],
            again: readable.clone(),
            readable,
            deleted: (0, libc::ENOENT),
            writable: vec![(4, libc::EVFILT_WRITE, libc::EV_ADD, 1)],
        }
    );
}

#[test]
fn a_real_pipe_reports_its_readiness() {
    check_pipe_readiness(Sim::new().run(pipe_readiness));
}

#[test]
fn a_real_pipe_reports_its_readiness_os_truth() {
    check_pipe_readiness(pipe_readiness());
}

/// One end of a socketpair made before the sim, and a `dup` of it as tokio's runtime makes of
/// its signal socketpair, register and report readable once the other end writes, and EOF once
/// that end closes.
fn socketpair_from_outside((mut tx, rx): (UnixStream, UnixStream)) -> (i32, Vec<Event>, bool) {
    let dup = unsafe { libc::dup(rx.as_raw_fd()) };
    let kq = unsafe { libc::kqueue() };
    let added = apply(kq, &[kev(dup, libc::EVFILT_READ, libc::EV_ADD, 1)]);
    snare::real(|| tx.write_all(b"x").unwrap());
    let readable = take(kq);
    snare::real(|| drop(tx));
    let eof = take(kq).first().is_some_and(|e| e.2 & libc::EV_EOF != 0);
    unsafe { libc::close(kq) };
    real_close(&[dup]);
    drop(rx);
    (added, readable, eof)
}

fn check_socketpair((added, readable, eof): (i32, Vec<Event>, bool)) {
    assert_eq!(added, 0);
    assert_eq!(readable, [(1, libc::EVFILT_READ, libc::EV_ADD, 1)]);
    assert!(eof, "EV_EOF once the writer is gone");
}

#[test]
fn a_socketpair_made_outside_the_sim_registers() {
    let pair = UnixStream::pair().unwrap();
    check_socketpair(Sim::new().run(move || socketpair_from_outside(pair)));
}

#[test]
fn a_socketpair_made_outside_the_sim_registers_os_truth() {
    check_socketpair(socketpair_from_outside(UnixStream::pair().unwrap()));
}

/// `EV_ONESHOT` reports once and deletes; `EV_CLEAR` reports once per readiness edge;
/// `EV_DISABLE` silences a ready registration until `EV_ENABLE`.
fn flags() -> Vec<Vec<u64>> {
    let [oneshot, clear, toggled] = [real_pipe(), real_pipe(), real_pipe()];
    let kq = unsafe { libc::kqueue() };
    apply(
        kq,
        &[
            kev(
                oneshot[0],
                libc::EVFILT_READ,
                libc::EV_ADD | libc::EV_ONESHOT,
                1,
            ),
            kev(
                clear[0],
                libc::EVFILT_READ,
                libc::EV_ADD | libc::EV_CLEAR,
                2,
            ),
            kev(
                toggled[0],
                libc::EVFILT_READ,
                libc::EV_ADD | libc::EV_DISABLE,
                3,
            ),
        ],
    );
    for pipe in [oneshot, clear, toggled] {
        real_write(pipe[1], b"ab");
    }
    let udatas = |kq| take(kq).into_iter().map(|e| e.0).collect::<Vec<_>>();
    let mut seen = vec![udatas(kq), udatas(kq)];
    apply(
        kq,
        &[kev(toggled[0], libc::EVFILT_READ, libc::EV_ENABLE, 3)],
    );
    seen.push(udatas(kq));
    real_read(clear[0], 2);
    seen.push(udatas(kq));
    real_write(clear[1], b"c");
    apply(
        kq,
        &[kev(toggled[0], libc::EVFILT_READ, libc::EV_DISABLE, 3)],
    );
    seen.push(udatas(kq));
    seen.push(vec![apply(
        kq,
        &[kev(oneshot[0], libc::EVFILT_READ, libc::EV_DELETE, 0)],
    ) as u64]);
    unsafe { libc::close(kq) };
    real_close(&[oneshot, clear, toggled].concat());
    seen
}

const FLAGS: [&[u64]; 6] = [&[1, 2], &[], &[3], &[3], &[2], &[libc::ENOENT as u64]];

#[test]
fn oneshot_clear_and_disable_on_real_descriptors() {
    assert_eq!(Sim::new().run(flags), FLAGS);
}

#[test]
fn oneshot_clear_and_disable_on_real_descriptors_os_truth() {
    assert_eq!(flags(), FLAGS);
}

#[derive(Debug, PartialEq)]
struct Refusals {
    closed_add: i32,
    closed_delete: i32,
    closed_enable: i32,
    receipts: Vec<(i64, u16)>,
    never_added: i32,
    dev_null: i32,
    file_readable_to_its_end: bool,
}

/// A closed descriptor is EBADF to add, as EV_RECEIPT reports per change, and ENOENT to delete or
/// enable, as is a registration the queue never had; `/dev/null`, whose device has no kqueue
/// filter, is EINVAL; a regular file is readable with the bytes left to read.
fn refusals() -> Refusals {
    const CLOSED: i32 = 9_999;
    assert!(snare::real(|| unsafe { libc::fcntl(CLOSED, libc::F_GETFD) }) < 0);
    let pipe = real_pipe();
    let kq = unsafe { libc::kqueue() };
    let [closed_add, closed_delete, closed_enable] =
        [libc::EV_ADD, libc::EV_DELETE, libc::EV_ENABLE]
            .map(|flags| apply(kq, &[kev(CLOSED, libc::EVFILT_READ, flags, 0)]));
    let changes = [
        kev(
            CLOSED,
            libc::EVFILT_READ,
            libc::EV_ADD | libc::EV_RECEIPT,
            0,
        ),
        kev(
            pipe[0],
            libc::EVFILT_READ,
            libc::EV_ADD | libc::EV_RECEIPT,
            0,
        ),
    ];
    let mut receipts = [kev(0, 0, 0, 0); 2];
    let n = unsafe {
        libc::kevent(
            kq,
            changes.as_ptr(),
            2,
            receipts.as_mut_ptr(),
            2,
            std::ptr::null(),
        )
    };
    let receipts = receipts[..n.max(0) as usize]
        .iter()
        .map(|r| (r.data as i64, r.flags & libc::EV_ERROR))
        .collect();
    let never_added = apply(kq, &[kev(pipe[0], libc::EVFILT_WRITE, libc::EV_DELETE, 0)]);
    let null = snare::real(|| unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY) });
    let dev_null = apply(kq, &[kev(null, libc::EVFILT_READ, libc::EV_ADD, 0)]);
    let exe = std::env::current_exe().unwrap();
    let size = snare::real(|| std::fs::metadata(&exe).unwrap().len()) as i64;
    let path = std::ffi::CString::new(exe.into_os_string().into_encoded_bytes()).unwrap();
    let file = snare::real(|| unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) });
    apply(kq, &[kev(file, libc::EVFILT_READ, libc::EV_ADD, 5)]);
    let file_readable_to_its_end = take(kq).iter().any(|e| e.0 == 5 && e.3 == size);
    unsafe { libc::close(kq) };
    real_close(&[pipe[0], pipe[1], null, file]);
    Refusals {
        closed_add,
        closed_delete,
        closed_enable,
        receipts,
        never_added,
        dev_null,
        file_readable_to_its_end,
    }
}

fn check_refusals(got: Refusals) {
    assert_eq!(
        got,
        Refusals {
            closed_add: libc::EBADF,
            closed_delete: libc::ENOENT,
            closed_enable: libc::ENOENT,
            receipts: vec![(libc::EBADF as i64, libc::EV_ERROR), (0, libc::EV_ERROR)],
            never_added: libc::ENOENT,
            dev_null: libc::EINVAL,
            file_readable_to_its_end: true,
        }
    );
}

#[test]
fn unusable_descriptors_are_refused() {
    check_refusals(Sim::new().run(refusals));
}

#[test]
fn unusable_descriptors_are_refused_os_truth() {
    check_refusals(refusals());
}

/// A kevent wait on a kqueue holding only an idle real pipe ends at its timeout with nothing
/// ready, the time it took read on the clock it runs under.
fn timed_wait(timeout: Duration) -> (i32, Duration) {
    let pipe = real_pipe();
    let kq = unsafe { libc::kqueue() };
    apply(kq, &[kev(pipe[0], libc::EVFILT_READ, libc::EV_ADD, 1)]);
    let span = libc::timespec {
        tv_sec: timeout.as_secs() as _,
        tv_nsec: timeout.subsec_nanos() as _,
    };
    let mut out = [kev(0, 0, 0, 0); 2];
    let start = Instant::now();
    let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 2, &span) };
    let took = start.elapsed();
    unsafe { libc::close(kq) };
    real_close(&pipe);
    (n, took)
}

#[test]
fn a_timed_wait_runs_on_the_sim_clock() {
    let wall = Instant::now();
    let (n, took) = Sim::builder()
        .deterministic()
        .stuck_after(Duration::from_secs(10))
        .build()
        .run(|| timed_wait(Duration::from_secs(30)));
    assert_eq!(n, 0);
    assert!(
        (Duration::from_secs(30)..Duration::from_millis(30_100)).contains(&took),
        "a 30 s kevent timeout took {took:?} of sim time"
    );
    assert!(wall.elapsed() < Duration::from_secs(10));
}

#[test]
fn a_timed_wait_os_truth() {
    let (n, took) = timed_wait(Duration::from_millis(50));
    assert_eq!(n, 0);
    assert!(took >= Duration::from_millis(50), "{took:?}");
}
