//! `SimBuilder::stuck_after`: a participant that keeps the sim busy without progress aborts the run
//! with a report, and nothing that waits, polls through hooked calls, holds a lease or blocks on a
//! paused clock trips it.
//!
//! A tripped watchdog aborts its process, so each stuck scenario runs as a child of this test
//! binary: the parent re-runs the binary on that one test with `SNARE_STUCK_CHILD` set and checks
//! that it failed and what it wrote. Without the variable the scenario returns at once.

use std::net::UdpSocket;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use snare::{Sim, SimBuilder};

const MS: Duration = Duration::from_millis(1);

/// Whether this process is the child a [`run_child`] started.
fn child() -> bool {
    std::env::var_os("SNARE_STUCK_CHILD").is_some()
}

/// Runs the test `name` of this binary in a child process and returns whether it succeeded and
/// its stderr, failing if it has not ended within a minute.
fn run_child(name: &str) -> (bool, String) {
    run_child_with_timeout(name, Duration::from_secs(60))
}

fn run_child_with_timeout(name: &str, timeout: Duration) -> (bool, String) {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", name, "--nocapture", "--test-threads=1"])
        .env("SNARE_STUCK_CHILD", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let reader = thread::spawn(move || {
        let mut out = String::new();
        std::io::Read::read_to_string(&mut stderr, &mut out).unwrap();
        out
    });
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > timeout {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!(
                "{name} never tripped the watchdog: {}",
                reader.join().unwrap()
            );
        }
        thread::sleep(10 * MS);
    };
    (status.success(), reader.join().unwrap())
}

/// The root participant spins on a flag only a sleeper would set, once its sleep ended: with the
/// discrete clock frozen by the spin, it never does.
fn spin_on_sleeper(builder: SimBuilder) {
    let sim = builder.stuck_after(300 * MS).build();
    sim.run(|| {
        let flag = Arc::new(AtomicBool::new(false));
        let set = flag.clone();
        let sleeper = thread::Builder::new()
            .name("sleeper".into())
            .spawn(move || {
                thread::sleep(Duration::from_secs(1));
                set.store(true, Ordering::Release);
            })
            .unwrap();
        thread::sleep(MS);
        while !flag.load(Ordering::Acquire) {
            std::hint::spin_loop();
        }
        sleeper.join().unwrap();
    });
}

#[test]
fn child_spinner_discrete() {
    if child() {
        spin_on_sleeper(Sim::builder());
    }
}

#[test]
fn child_spinner_deterministic() {
    if child() {
        spin_on_sleeper(Sim::builder().deterministic());
    }
}

fn assert_tripped(name: &str, deterministic: bool) {
    let (ok, stderr) = run_child(name);
    assert!(!ok, "{name} should have aborted:\n{stderr}");
    assert!(stderr.contains("snare: stuck:"), "{stderr}");
    assert!(stderr.contains("stuck_after 300ms"), "{stderr}");
    // Linux keeps 15 bytes of a thread's name (man 3 pthread_setname_np).
    assert!(
        stderr.contains(&format!("running  {}", &name[..15])),
        "names the spinning participant:\n{stderr}"
    );
    assert!(
        stderr.contains("blocked  sleeper"),
        "names the blocked sleeper:\n{stderr}"
    );
    let baton = stderr
        .lines()
        .find(|line| line.ends_with("holds the deterministic schedule's baton"));
    assert_eq!(baton.is_some(), deterministic, "{stderr}");
    if let Some(line) = baton {
        assert!(line.trim_start().starts_with(&name[..15]), "{stderr}");
    }
}

#[test]
fn spinner_trips_watchdog_on_discrete_clock() {
    if !child() {
        assert_tripped("child_spinner_discrete", false);
    }
}

#[test]
fn spinner_trips_watchdog_under_deterministic() {
    if !child() {
        assert_tripped("child_spinner_deterministic", true);
    }
}

fn spin_holding_stderr(builder: SimBuilder) {
    builder.stuck_after(100 * MS).build().run(|| {
        let _stderr = std::io::stderr().lock();
        loop {
            std::hint::spin_loop();
        }
    });
}

#[test]
fn child_spinner_holding_stderr_discrete() {
    if child() {
        spin_holding_stderr(Sim::builder());
    }
}

#[test]
fn child_spinner_holding_stderr_deterministic() {
    if child() {
        spin_holding_stderr(Sim::builder().deterministic());
    }
}

#[test]
fn a_stderr_lock_held_by_a_stuck_participant_cannot_block_the_watchdog() {
    if !child() {
        for name in [
            "child_spinner_holding_stderr_discrete",
            "child_spinner_holding_stderr_deterministic",
        ] {
            let (ok, stderr) = run_child_with_timeout(name, Duration::from_secs(10));
            assert!(!ok, "{name} should have aborted: {stderr}");
        }
    }
}

#[cfg(unix)]
#[test]
fn child_spinner_with_a_full_stderr_pipe() {
    if !child() {
        return;
    }
    Sim::builder().stuck_after(100 * MS).build().run(|| {
        let flags = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let bytes = [b'x'; 512];
        loop {
            let wrote =
                unsafe { libc::write(libc::STDERR_FILENO, bytes.as_ptr().cast(), bytes.len()) };
            if wrote < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().kind(),
                    std::io::ErrorKind::WouldBlock
                );
                break;
            }
        }
        assert_eq!(
            unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_SETFL, flags) },
            0
        );
        loop {
            std::hint::spin_loop();
        }
    });
}

#[cfg(unix)]
#[test]
fn a_full_stderr_pipe_cannot_block_the_watchdog() {
    if child() {
        return;
    }
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_spinner_with_a_full_stderr_pipe",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SNARE_STUCK_CHILD", "1")
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if start.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("a blocked stderr pipe prevented the watchdog from aborting");
        }
        thread::sleep(10 * MS);
    };
    assert!(!status.success());
}

/// Work a stuck watchdog must sit through: long virtual sleeps, a receive polled through
/// non-blocking calls until a datagram due later arrives (each call is charged a microsecond, so
/// the poll itself carries the clock there), a lease held across real work
/// longer than the threshold, and channel hand-offs between threads.
fn waiting_work(sim: &Sim) {
    sim.run(|| {
        let rx = UdpSocket::bind("127.0.0.1:9900").unwrap();
        rx.set_nonblocking(true).unwrap();
        let tx = thread::spawn(|| {
            thread::sleep(30 * MS);
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            s.send_to(b"late", "127.0.0.1:9900").unwrap();
        });
        let mut buf = [0u8; 8];
        let n = loop {
            match rx.recv(&mut buf) {
                Ok(n) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(&buf[..n], b"late");
        tx.join().unwrap();

        {
            let _lease = snare::sched::busy("real work");
            snare::real(|| thread::sleep(200 * MS));
        }

        let (to_peer, from_main) = std::sync::mpsc::channel::<u32>();
        let (to_main, from_peer) = std::sync::mpsc::channel::<u32>();
        let peer = thread::spawn(move || {
            for v in from_main {
                thread::sleep(Duration::from_secs(1));
                to_main.send(v + 1).unwrap();
            }
        });
        for i in 0..5 {
            to_peer.send(i).unwrap();
            assert_eq!(from_peer.recv().unwrap(), i + 1);
        }
        drop(to_peer);
        peer.join().unwrap();
    });
}

#[test]
fn waiting_and_polling_never_trip_on_discrete_clock() {
    if !child() {
        waiting_work(&Sim::builder().stuck_after(50 * MS).build());
    }
}

#[test]
fn waiting_and_polling_never_trip_under_deterministic() {
    if !child() {
        waiting_work(&Sim::builder().deterministic().stuck_after(50 * MS).build());
    }
}

#[test]
fn paused_clock_waits_never_trip() {
    if child() {
        return;
    }
    let sim = Sim::builder().stuck_after(50 * MS).build();
    sim.pause_time();
    let time = sim.time();
    let resumer = thread::spawn(move || {
        thread::sleep(300 * MS);
        time.resume();
    });
    sim.run(|| {
        let start = Instant::now();
        thread::sleep(Duration::from_secs(2));
        assert!(start.elapsed() >= Duration::from_secs(2));
    });
    resumer.join().unwrap();
}

/// The instants each of two threads reads between channel hand-offs, which a deterministic run
/// replays exactly.
fn ping_pong_reads(builder: SimBuilder) -> Vec<Duration> {
    let sim = builder.deterministic().seed(7).build();
    sim.run(|| {
        let origin = Instant::now();
        let (tx, rx) = std::sync::mpsc::channel::<Duration>();
        let worker = thread::spawn(move || {
            let mut seen = Vec::new();
            for _ in 0..20 {
                thread::sleep(3 * MS);
                seen.push(origin.elapsed());
                tx.send(origin.elapsed()).unwrap();
            }
            seen
        });
        let mut reads: Vec<Duration> = rx.iter().collect();
        reads.extend(worker.join().unwrap());
        reads
    })
}

#[test]
fn watchdog_leaves_deterministic_runs_unchanged() {
    if !child() {
        let plain = ping_pong_reads(Sim::builder());
        let watched = ping_pong_reads(Sim::builder().stuck_after(20 * MS));
        assert_eq!(plain, watched);
    }
}

/// A participant spins on the clock (`while Instant::now() < deadline {}`) while the clock is
/// paused: the spin cannot move a held clock, so the watchdog sees it busy with no progress.
fn clock_spin_on_paused(builder: SimBuilder) {
    let sim = builder.stuck_after(300 * MS).build();
    sim.pause_time();
    sim.run(|| {
        let deadline = Instant::now() + MS;
        while Instant::now() < deadline {}
    });
}

#[test]
fn child_clock_spin_paused_discrete() {
    if child() {
        clock_spin_on_paused(Sim::builder());
    }
}

#[test]
fn child_clock_spin_paused_deterministic() {
    if child() {
        clock_spin_on_paused(Sim::builder().deterministic());
    }
}

#[test]
fn clock_spin_on_a_paused_clock_trips_the_watchdog() {
    if child() {
        return;
    }
    for name in [
        "child_clock_spin_paused_discrete",
        "child_clock_spin_paused_deterministic",
    ] {
        let (ok, stderr) = run_child(name);
        assert!(!ok, "{name} should have aborted:\n{stderr}");
        assert!(stderr.contains("snare: stuck:"), "{stderr}");
    }
}

/// A clock spin that moves time is progress: a spin of three hours of virtual time that burns real
/// time on every turn, long past the threshold, never trips the watchdog.
fn slow_clock_spin(builder: SimBuilder) {
    let threshold = 300 * MS;
    let sim = builder.stuck_after(threshold).build();
    let real = sim.run(|| {
        let start = Instant::now();
        let real = snare::real(Instant::now);
        while Instant::now() < start + Duration::from_secs(10_800) {
            let burn = snare::real(Instant::now);
            while snare::real(|| burn.elapsed()) < Duration::from_micros(200) {}
        }
        snare::real(|| real.elapsed())
    });
    assert!(
        real > threshold * 4,
        "the spin outlasted the threshold: {real:?}"
    );
}

#[test]
fn child_slow_clock_spin_discrete() {
    if child() {
        slow_clock_spin(Sim::builder());
    }
}

#[test]
fn child_slow_clock_spin_deterministic() {
    if child() {
        slow_clock_spin(Sim::builder().deterministic());
    }
}

#[test]
fn a_clock_spin_that_moves_time_never_trips() {
    if child() {
        return;
    }
    for name in [
        "child_slow_clock_spin_discrete",
        "child_slow_clock_spin_deterministic",
    ] {
        let (ok, stderr) = run_child(name);
        assert!(ok, "{name} tripped:\n{stderr}");
    }
}
