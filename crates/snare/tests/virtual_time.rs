#![cfg(unix)]

//! The discrete-event virtual clock, a plain `Sim`'s default: deterministic time that advances by
//! jumping to the next pending sleep/timeout once the sim is quiescent — so a blocked wait with a
//! deadline skips straight there instead of waiting on the wall clock, and multi-second sleeps
//! finish in microseconds of real time while virtual time still moves forward — and by a
//! microsecond per call that returns without blocking, so a busy-poll cannot freeze it.

use std::net::UdpSocket;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use mio::{Events, Interest, Poll, Token};
use snare::Sim;

fn vsim() -> Sim {
    Sim::builder().virtual_clock().build()
}

#[test]
fn reads_a_fixed_epoch_without_ticking() {
    vsim().run(|| {
        // Discrete: successive reads do not advance time on their own.
        let a = Instant::now();
        let b = Instant::now();
        assert_eq!(a, b);
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(now.as_secs(), 1_700_000_000);
    });
}

#[test]
fn lone_sleep_skips_virtual_time() {
    let real = Instant::now();
    vsim().run(|| {
        let start = Instant::now();
        std::thread::sleep(Duration::from_secs(3600));
        assert!(
            start.elapsed() >= Duration::from_secs(3600),
            "virtual hour elapsed"
        );
    });
    // The whole run took a tiny fraction of a real second despite the virtual hour.
    assert!(real.elapsed() < Duration::from_secs(60));
}

#[test]
fn advance_time_steps_the_clock() {
    let sim = vsim();
    sim.run(|| {
        let start = Instant::now();
        assert!(start.elapsed() < Duration::from_millis(1));
        // nothing moves time on its own
    });
    sim.advance_time(Duration::from_secs(5));
    sim.run(|| {
        // The explicit step is visible as realtime moving 5s past the epoch.
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(now.as_secs(), 1_700_000_005);
    });
}

#[test]
fn time_skips_across_threads_to_a_timer() {
    vsim().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = receiver.local_addr().unwrap();
        let start = Instant::now();

        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            // Sleep ten virtual minutes, then send. Meanwhile the receiver is parked in recv_from;
            // with both threads blocked the clock jumps to this wake-up.
            std::thread::sleep(Duration::from_secs(600));
            s.send_to(b"tick", addr).unwrap();
        });

        let mut buf = [0u8; 8];
        let (n, _) = receiver.recv_from(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"tick");
        sender.join().unwrap();
        assert!(
            start.elapsed() >= Duration::from_secs(600),
            "clock advanced to the timer"
        );
    });
}

#[test]
fn run_testers_join_works_under_virtual_time() {
    // The classic tester orchestration — a scripted peer driven to a deadline, joined by main —
    // works under the virtual clock: `pthread_join` counts toward quiescence, so the tester's
    // `until_after` deadline is reached by the time-skip instead of real wall time.
    use snare::{Line, TesterAction, connect_tester, run_testers};
    let real = Instant::now();
    vsim().run(|| {
        let server = connect_tester::<Line>("127.0.0.7:9710")
            .then_action(|msg, _| TesterAction::Send(Line(format!("echo:{}", msg.0))))
            .until_after(Duration::from_secs(5));

        let client = std::thread::spawn(|| {
            use std::io::{BufRead, BufReader, Write};
            let mut s = std::net::TcpStream::connect("127.0.0.7:9710").unwrap();
            s.write_all(b"hi\n").unwrap();
            let mut line = String::new();
            BufReader::new(s).read_line(&mut line).unwrap();
            line
        });

        run_testers!(server);
        assert_eq!(client.join().unwrap(), "echo:hi\n");
    });
    // The tester's five-second lifetime elapsed in virtual time, not real time.
    assert!(
        real.elapsed() < Duration::from_secs(5),
        "ran as-fast-as-possible, not for 5 real s"
    );
}

#[test]
fn poll_timeout_skips_virtual_time() {
    // A readiness wait with a finite timeout (here `mio`'s poll, which is `epoll_wait`/`kevent`
    // under the hood) registers that timeout as a pending virtual timer, so when the sim is
    // quiescent the clock jumps straight to it rather than treating the timeout as a deadlock.
    let real = Instant::now();
    vsim().run(|| {
        let mut poll = Poll::new().unwrap();
        let mut events = Events::with_capacity(8);
        let mut sock = mio::net::UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        poll.registry()
            .register(&mut sock, Token(0), Interest::READABLE)
            .unwrap();

        let start = Instant::now();
        // Nothing will ever make the socket readable, so the poll must run its full timeout.
        poll.poll(&mut events, Some(Duration::from_secs(30)))
            .unwrap();
        assert_eq!(events.iter().count(), 0, "no fd became ready");
        // Virtual time jumped to the ~30s timeout (not ~0 as a deadlock give-up would, nor the real
        // 30s). The small tolerance absorbs macOS mach-timebase rounding in `Instant`'s ns↔tick trip.
        let advanced = start.elapsed();
        assert!(
            (Duration::from_millis(29_900)..=Duration::from_secs(31)).contains(&advanced),
            "virtual time reached the timeout, got {advanced:?}"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "ran as-fast-as-possible, not 30 real s"
    );
}

#[test]
fn a_busy_poll_lets_virtual_time_reach_a_sleeper() {
    // The receiver spins on a non-blocking receive and never blocks or yields; the sender sleeps
    // ten virtual milliseconds first. Each empty receive costs a microsecond of virtual time, so
    // the clock crawls to the sender's wake-up instead of freezing under the spin.
    let real = Instant::now();
    Sim::new().run(|| {
        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        receiver.set_nonblocking(true).unwrap();
        let addr = receiver.local_addr().unwrap();
        let start = Instant::now();
        let sender = std::thread::spawn(move || {
            let s = UdpSocket::bind("127.0.0.1:0").unwrap();
            std::thread::sleep(Duration::from_millis(10));
            s.send_to(b"late", addr).unwrap();
        });
        let mut buf = [0u8; 8];
        let n = loop {
            match receiver.recv_from(&mut buf) {
                Ok((n, _)) => break n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(e) => panic!("{e}"),
            }
        };
        assert_eq!(&buf[..n], b"late");
        sender.join().unwrap();
        assert!(
            start.elapsed() >= Duration::from_millis(10),
            "the sender's sleep elapsed"
        );
    });
    assert!(
        real.elapsed() < Duration::from_secs(30),
        "the spin did not stall the clock"
    );
}

#[test]
fn wall_clock_opts_out() {
    Sim::builder().wall_clock().build().run(|| {
        let real = std::time::Instant::now();
        std::thread::sleep(Duration::from_millis(30));
        assert!(
            real.elapsed() >= Duration::from_millis(30),
            "slept in real time"
        );
        let a = Instant::now();
        let b = Instant::now();
        assert!(b >= a);
    });
}

#[test]
fn deadlock_without_a_timer_still_gives_up() {
    // With no pending timer, a wait that can never be satisfied must still return (EAGAIN) rather
    // than hang — the quiescence check falls through to deadlock detection when time-skip can't help.
    vsim().run(|| {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut buf = [0u8; 8];
        // No sender, no timer: the blocking recv detects quiescence and returns an error.
        assert!(s.recv_from(&mut buf).is_err());
    });
}
