#![cfg(unix)]

//! Real descriptors in a sim's readiness waits. A pipe stays a real descriptor in a sim (a child
//! process must be able to inherit it), so a `poll`, `epoll_wait` or `kevent` that also waits on
//! simulated sockets has to block on the pipe as well: it returns as soon as a write by another
//! thread of the sim or by a child process makes it readable, and never spins meanwhile.
//!
//! A pipe only the sim's own threads write is part of the sim: the wait ends at the sim time of
//! the write, time skips past a sleeping writer as it would for a socket, and a deterministic run
//! replays. A descriptor something outside the sim may write (a child process holding a pipe's
//! write end) holds the sim's clock to real time while a thread waits on it, so a timeout cannot
//! pass before the child has had that long to answer.

use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use snare::Sim;

/// A pipe no child process inherits unless it is handed an end.
fn pipe() -> [i32; 2] {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    for fd in fds {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    fds
}

fn write_byte(fd: i32) {
    assert_eq!(unsafe { libc::write(fd, b"x".as_ptr().cast(), 1) }, 1);
}

fn read_byte(fd: i32) -> u8 {
    let mut byte = 0u8;
    assert_eq!(unsafe { libc::read(fd, (&raw mut byte).cast(), 1) }, 1);
    byte
}

fn close(fds: &[i32]) {
    for &fd in fds {
        unsafe { libc::close(fd) };
    }
}

/// `poll` over `fds` (all for `POLLIN`): its return and each `revents`.
fn poll_in(fds: &[i32], timeout_ms: i32) -> (i32, Vec<i16>) {
    let mut pfds: Vec<libc::pollfd> = fds
        .iter()
        .map(|&fd| libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        })
        .collect();
    let n = unsafe { libc::poll(pfds.as_mut_ptr(), pfds.len() as _, timeout_ms) };
    (n, pfds.iter().map(|p| p.revents).collect())
}

/// Held by every test of this file: a child one test spawns would otherwise inherit a pipe another
/// test makes between `pipe` and setting `FD_CLOEXEC`, and hold its write end open.
static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn plain() -> Sim {
    Sim::builder().stuck_after(Duration::from_secs(20)).build()
}

fn deterministic() -> Sim {
    Sim::builder()
        .deterministic()
        .stuck_after(Duration::from_secs(20))
        .build()
}

/// What a waiter on a pipe and a UDP socket saw: the wait's return, its `revents`, and the sim
/// time it took.
type Seen = (i32, Vec<i16>, Duration);

/// A thread of the sim writes the pipe after a 100 ms sleep while this one polls the pipe and an
/// idle UDP socket with `timeout_ms`.
fn poll_pipe_written_by_a_sim_thread(timeout_ms: i32) -> Seen {
    let [r, w] = pipe();
    let udp = UdpSocket::bind("127.0.0.1:7300").unwrap();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        write_byte(w);
    });
    let start = Instant::now();
    let (n, revents) = poll_in(&[r, udp.as_raw_fd()], timeout_ms);
    let took = start.elapsed();
    writer.join().unwrap();
    assert_eq!(read_byte(r), b'x');
    close(&[r, w]);
    (n, revents, took)
}

fn check_written_at_100ms((n, revents, took): Seen) {
    assert_eq!((n, revents), (1, vec![libc::POLLIN, 0]));
    assert!(
        (Duration::from_millis(100)..Duration::from_millis(101)).contains(&took),
        "the poll took {took:?} of sim time"
    );
}

#[test]
fn poll_wakes_on_a_pipe_written_by_a_sim_thread() {
    let _serial = serial();
    let wall = Instant::now();
    check_written_at_100ms(plain().run(|| poll_pipe_written_by_a_sim_thread(5_000)));
    check_written_at_100ms(plain().run(|| poll_pipe_written_by_a_sim_thread(-1)));
    assert!(
        wall.elapsed() < Duration::from_secs(5),
        "{:?}",
        wall.elapsed()
    );
}

#[test]
fn poll_wakes_on_a_pipe_written_by_a_sim_thread_deterministic() {
    let _serial = serial();
    let wall = Instant::now();
    let first = deterministic().run(|| poll_pipe_written_by_a_sim_thread(5_000));
    let again = deterministic().run(|| poll_pipe_written_by_a_sim_thread(5_000));
    assert_eq!(first, again);
    check_written_at_100ms(first);
    check_written_at_100ms(deterministic().run(|| poll_pipe_written_by_a_sim_thread(-1)));
    assert!(
        wall.elapsed() < Duration::from_secs(5),
        "{:?}",
        wall.elapsed()
    );
}

/// A poll on a pipe nobody writes, beside a UDP socket, times out on the sim clock at once.
#[test]
fn poll_on_an_idle_pipe_times_out_on_the_sim_clock() {
    let _serial = serial();
    let wall = Instant::now();
    for sim in [plain(), deterministic()] {
        let (n, took) = sim.run(|| {
            let [r, w] = pipe();
            let udp = UdpSocket::bind("127.0.0.1:7301").unwrap();
            let start = Instant::now();
            let (n, _) = poll_in(&[r, udp.as_raw_fd()], 30_000);
            let took = start.elapsed();
            close(&[r, w]);
            (n, took)
        });
        assert_eq!(n, 0);
        assert!(
            (Duration::from_secs(30)..Duration::from_millis(30_001)).contains(&took),
            "{took:?}"
        );
    }
    assert!(
        wall.elapsed() < Duration::from_secs(5),
        "{:?}",
        wall.elapsed()
    );
}

/// A poll on a pipe alone, written by a sim thread after a sleep.
#[test]
fn poll_on_a_pipe_alone_wakes_on_a_sim_thread_write() {
    let _serial = serial();
    for sim in [plain(), deterministic()] {
        let took = sim.run(|| {
            let [r, w] = pipe();
            let writer = std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(40));
                write_byte(w);
            });
            let start = Instant::now();
            let (n, revents) = poll_in(&[r], 5_000);
            let took = start.elapsed();
            assert_eq!((n, revents), (1, vec![libc::POLLIN]));
            writer.join().unwrap();
            close(&[r, w]);
            took
        });
        assert!(
            (Duration::from_millis(40)..Duration::from_millis(41)).contains(&took),
            "{took:?}"
        );
    }
}

/// A sim thread closing the pipe's write end wakes a poll on the read end with a hang-up.
#[test]
fn poll_wakes_on_the_write_end_closed_by_a_sim_thread() {
    let _serial = serial();
    let (n, revents, took) = plain().run(|| {
        let [r, w] = pipe();
        let udp = UdpSocket::bind("127.0.0.1:7302").unwrap();
        let closer = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            close(&[w]);
        });
        let start = Instant::now();
        let (n, revents) = poll_in(&[r, udp.as_raw_fd()], -1);
        let took = start.elapsed();
        closer.join().unwrap();
        close(&[r]);
        (n, revents, took)
    });
    assert_eq!(n, 1);
    assert_ne!(revents[0] & libc::POLLHUP, 0, "{revents:?}");
    assert!(
        (Duration::from_millis(30)..Duration::from_millis(31)).contains(&took),
        "{took:?}"
    );
}

#[cfg(target_os = "linux")]
fn wait_set(fds: &[i32], timeout_ms: i32) -> (i32, Vec<u64>) {
    let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    assert!(ep >= 0);
    for &fd in fds {
        let mut event = libc::epoll_event {
            events: libc::EPOLLIN as u32,
            u64: fd as u64,
        };
        assert_eq!(
            unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut event) },
            0
        );
    }
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    let n = unsafe { libc::epoll_wait(ep, out.as_mut_ptr(), 4, timeout_ms) };
    close(&[ep]);
    (n, out[..n.max(0) as usize].iter().map(|e| e.u64).collect())
}

#[cfg(target_os = "macos")]
fn wait_set(fds: &[i32], timeout_ms: i32) -> (i32, Vec<u64>) {
    let kq = unsafe { libc::kqueue() };
    assert!(kq >= 0);
    let changes: Vec<libc::kevent> = fds
        .iter()
        .map(|&fd| libc::kevent {
            ident: fd as usize,
            filter: libc::EVFILT_READ,
            flags: libc::EV_ADD,
            fflags: 0,
            data: 0,
            udata: fd as usize as *mut libc::c_void,
        })
        .collect();
    let applied = unsafe {
        libc::kevent(
            kq,
            changes.as_ptr(),
            changes.len() as i32,
            std::ptr::null_mut(),
            0,
            std::ptr::null(),
        )
    };
    assert_eq!(applied, 0);
    let span = libc::timespec {
        tv_sec: (timeout_ms / 1000) as _,
        tv_nsec: ((timeout_ms % 1000) * 1_000_000) as _,
    };
    let timeout = if timeout_ms < 0 {
        std::ptr::null()
    } else {
        &raw const span
    };
    let mut out: [libc::kevent; 4] = unsafe { std::mem::zeroed() };
    let n = unsafe { libc::kevent(kq, std::ptr::null(), 0, out.as_mut_ptr(), 4, timeout) };
    close(&[kq]);
    (
        n,
        out[..n.max(0) as usize]
            .iter()
            .map(|e| e.udata as u64)
            .collect(),
    )
}

/// [`poll_pipe_written_by_a_sim_thread`] through an epoll set (Linux) or a kqueue (macOS): the
/// wait's return, whether what it reported was the pipe, and the sim time it took.
fn wait_set_on_pipe_written_by_a_sim_thread(timeout_ms: i32) -> (i32, bool, Duration) {
    let [r, w] = pipe();
    let udp = UdpSocket::bind("127.0.0.1:7303").unwrap();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(100));
        write_byte(w);
    });
    let start = Instant::now();
    let (n, ready) = wait_set(&[r, udp.as_raw_fd()], timeout_ms);
    let took = start.elapsed();
    writer.join().unwrap();
    assert_eq!(read_byte(r), b'x');
    close(&[r, w]);
    (n, ready == [r as u64], took)
}

fn check_set_written_at_100ms((n, pipe, took): (i32, bool, Duration)) {
    assert_eq!((n, pipe), (1, true));
    assert!(
        (Duration::from_millis(100)..Duration::from_millis(101)).contains(&took),
        "the wait took {took:?} of sim time"
    );
}

#[test]
fn readiness_set_wakes_on_a_pipe_written_by_a_sim_thread() {
    let _serial = serial();
    let wall = Instant::now();
    check_set_written_at_100ms(plain().run(|| wait_set_on_pipe_written_by_a_sim_thread(5_000)));
    check_set_written_at_100ms(plain().run(|| wait_set_on_pipe_written_by_a_sim_thread(-1)));
    let first = deterministic().run(|| wait_set_on_pipe_written_by_a_sim_thread(5_000));
    let again = deterministic().run(|| wait_set_on_pipe_written_by_a_sim_thread(5_000));
    assert_eq!(first, again);
    check_set_written_at_100ms(first);
    check_set_written_at_100ms(
        deterministic().run(|| wait_set_on_pipe_written_by_a_sim_thread(-1)),
    );
    assert!(
        wall.elapsed() < Duration::from_secs(5),
        "{:?}",
        wall.elapsed()
    );
}

/// An epoll set (Linux) or kqueue (macOS) holding `fd` edge-triggered (`EPOLLET`, `EV_CLEAR`) for
/// reading.
#[cfg(target_os = "linux")]
fn edge_set(fd: i32) -> i32 {
    let ep = unsafe { libc::epoll_create1(libc::EPOLL_CLOEXEC) };
    let mut event = libc::epoll_event {
        events: (libc::EPOLLIN | libc::EPOLLET) as u32,
        u64: fd as u64,
    };
    assert_eq!(
        unsafe { libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, fd, &mut event) },
        0
    );
    ep
}

#[cfg(target_os = "macos")]
fn edge_set(fd: i32) -> i32 {
    let kq = unsafe { libc::kqueue() };
    let change = libc::kevent {
        ident: fd as usize,
        filter: libc::EVFILT_READ,
        flags: libc::EV_ADD | libc::EV_CLEAR,
        fflags: 0,
        data: 0,
        udata: std::ptr::null_mut(),
    };
    let applied =
        unsafe { libc::kevent(kq, &change, 1, std::ptr::null_mut(), 0, std::ptr::null()) };
    assert_eq!(applied, 0);
    kq
}

/// How many events a zero-timeout wait on `set` reports.
#[cfg(target_os = "linux")]
fn edges_now(set: i32) -> i32 {
    let mut out = [libc::epoll_event { events: 0, u64: 0 }; 4];
    unsafe { libc::epoll_wait(set, out.as_mut_ptr(), 4, 0) }
}

#[cfg(target_os = "macos")]
fn edges_now(set: i32) -> i32 {
    let mut out: [libc::kevent; 4] = unsafe { std::mem::zeroed() };
    let zero = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::kevent(set, std::ptr::null(), 0, out.as_mut_ptr(), 4, &zero) }
}

/// What an edge-triggered set reports for a pipe: a write, nothing more until the next write
/// (even when no wait saw the pipe empty in between), and the hang-up of its write end.
fn edges_of_a_pipe() -> Vec<i32> {
    let [r, w] = pipe();
    let set = edge_set(r);
    write_byte(w);
    let mut seen = vec![edges_now(set), edges_now(set)];
    read_byte(r);
    write_byte(w);
    seen.push(edges_now(set));
    read_byte(r);
    close(&[w]);
    seen.push(edges_now(set));
    close(&[set, r]);
    seen
}

#[test]
fn an_edge_triggered_set_reports_each_change_of_a_pipe() {
    let _serial = serial();
    assert_eq!(plain().run(edges_of_a_pipe), vec![1, 0, 1, 1]);
    assert_eq!(deterministic().run(edges_of_a_pipe), vec![1, 0, 1, 1]);
}

#[test]
fn an_edge_triggered_set_reports_each_change_of_a_pipe_os_truth() {
    let _serial = serial();
    assert_eq!(edges_of_a_pipe(), vec![1, 0, 1, 1]);
}

/// A child process holding a pipe's write end writes it after `delay_ms` while this thread polls
/// the read end and an idle UDP socket with `timeout_ms`: the poll's return and `revents`, and
/// the sim and real time it took.
fn poll_pipe_written_by_a_child(
    delay_ms: u64,
    timeout_ms: i32,
) -> (i32, Vec<i16>, Duration, Duration) {
    let [r, w] = pipe();
    let udp = UdpSocket::bind("127.0.0.1:7304").unwrap();
    let writer = unsafe { std::os::fd::OwnedFd::from_raw_fd(w) };
    let mut child = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("sleep {}; printf x", delay_ms as f64 / 1000.0))
        .stdout(writer)
        .spawn()
        .unwrap();
    let start = Instant::now();
    let real = snare::real(Instant::now);
    let (n, revents) = poll_in(&[r, udp.as_raw_fd()], timeout_ms);
    let took = start.elapsed();
    let real = snare::real(|| real.elapsed());
    child.wait().unwrap();
    close(&[r]);
    (n, revents, took, real)
}

#[test]
fn poll_wakes_on_a_pipe_written_by_a_child() {
    let _serial = serial();
    for sim in [plain(), deterministic()] {
        let (n, revents, took, real) = sim.run(|| poll_pipe_written_by_a_child(200, 10_000));
        assert_eq!(
            (n, revents[0] & libc::POLLIN, revents[1]),
            (1, libc::POLLIN, 0)
        );
        assert!(real >= Duration::from_millis(200), "{real:?}");
        assert!(
            took <= real + Duration::from_millis(5),
            "{took:?} against {real:?}"
        );
    }
}

/// A child slower than the poll's timeout: the timeout passes on the sim clock, but no sooner
/// than in real time, so the child had as long to answer as the timeout says.
#[test]
fn a_timeout_waiting_on_a_child_runs_in_real_time() {
    let _serial = serial();
    for sim in [plain(), deterministic()] {
        let (n, _, took, real) = sim.run(|| poll_pipe_written_by_a_child(2_000, 300));
        assert_eq!(n, 0);
        assert!(
            (Duration::from_millis(300)..Duration::from_millis(301)).contains(&took),
            "{took:?}"
        );
        assert!(real >= Duration::from_millis(295), "{real:?}");
        assert!(real < Duration::from_millis(1_900), "{real:?}");
    }
}

async fn child_output() -> std::process::Output {
    tokio::process::Command::new("sh")
        .arg("-c")
        .arg("sleep 0.3; echo out; echo err >&2")
        .output()
        .await
        .unwrap()
}

/// Runs `body` on a tokio runtime built in a fresh sim of each kind (`multi_thread` picks the
/// runtime), and checks the child's output and that the sim's clock ran no faster than real time
/// while it waited for the child.
fn in_tokio(
    multi_thread: bool,
    body: impl Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = std::process::Output>>>
    + Send
    + Sync,
) {
    for sim in [plain(), deterministic()] {
        let (output, took, real) = sim.run(|| {
            let runtime = if multi_thread {
                tokio::runtime::Builder::new_multi_thread()
                    .worker_threads(2)
                    .enable_all()
                    .build()
            } else {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
            }
            .unwrap();
            let start = Instant::now();
            let real = snare::real(Instant::now);
            let output = runtime.block_on(body());
            (output, start.elapsed(), snare::real(|| real.elapsed()))
        });
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
        assert!(
            took <= real + Duration::from_millis(20),
            "{took:?} of sim time against {real:?} of real time"
        );
    }
}

#[test]
fn tokio_process_output_in_a_sim() {
    let _serial = serial();
    in_tokio(false, || Box::pin(child_output()));
    in_tokio(true, || Box::pin(child_output()));
}

#[test]
fn tokio_process_output_under_a_timeout_in_a_sim() {
    let _serial = serial();
    let timed = || -> std::pin::Pin<Box<dyn std::future::Future<Output = std::process::Output>>> {
        Box::pin(async {
            tokio::time::timeout(Duration::from_secs(1), child_output())
                .await
                .expect("the child answers within the timeout")
        })
    };
    in_tokio(false, timed);
    in_tokio(true, timed);
}

#[test]
fn tokio_process_output_beside_a_ticking_task() {
    let _serial = serial();
    in_tokio(true, || {
        Box::pin(async {
            let ticker = tokio::spawn(async {
                loop {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            });
            let output = tokio::time::timeout(Duration::from_secs(1), child_output())
                .await
                .expect("the child answers within the timeout");
            ticker.abort();
            output
        })
    });
}

/// `Child::wait` with nothing else to wake its task: the child's exit reaches tokio's `SIGCHLD`
/// handler on a thread of the sim (macOS), or its pidfd (Linux), well before the timeout.
#[test]
fn tokio_process_wait_in_a_sim() {
    let _serial = serial();
    for sim in [plain(), deterministic()] {
        let (status, real) = sim.run(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let real = snare::real(Instant::now);
                    let mut child = tokio::process::Command::new("sh")
                        .arg("-c")
                        .arg("sleep 0.2")
                        .spawn()
                        .unwrap();
                    let status = tokio::time::timeout(Duration::from_secs(30), child.wait())
                        .await
                        .expect("the child's exit is seen within the timeout")
                        .unwrap();
                    (status, snare::real(|| real.elapsed()))
                })
        });
        assert!(status.success());
        assert!(real >= Duration::from_millis(200), "{real:?}");
        assert!(real < Duration::from_secs(10), "{real:?}");
    }
}

/// `std::process::Command::output` reads the child's two pipes with `poll`.
#[test]
fn std_process_output_in_a_sim() {
    let _serial = serial();
    for sim in [plain(), deterministic()] {
        let output = sim.run(|| {
            std::process::Command::new("sh")
                .arg("-c")
                .arg("sleep 0.1; echo out; echo err >&2")
                .output()
                .unwrap()
        });
        assert!(output.status.success(), "{output:?}");
        assert_eq!(output.stdout, b"out\n");
        assert_eq!(output.stderr, b"err\n");
    }
}

/// While a child process runs the sim's clock moves no faster than real time: a sim thread's
/// sleep lasts until the child has exited, then skips the rest at once.
#[test]
fn a_running_child_holds_the_clock_to_real_time() {
    let _serial = serial();
    for sim in [plain(), deterministic()] {
        let (took, real) = sim.run(|| {
            let mut child = std::process::Command::new("sh")
                .arg("-c")
                .arg("sleep 0.3")
                .spawn()
                .unwrap();
            let start = Instant::now();
            let real = snare::real(Instant::now);
            std::thread::sleep(Duration::from_secs(2));
            let spans = (start.elapsed(), snare::real(|| real.elapsed()));
            child.wait().unwrap();
            spans
        });
        assert!(
            (Duration::from_secs(2)..Duration::from_millis(2_001)).contains(&took),
            "{took:?}"
        );
        assert!(real >= Duration::from_millis(290), "{real:?}");
        assert!(real < Duration::from_millis(1_900), "{real:?}");
    }
}
