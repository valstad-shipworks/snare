//! Behaviour pins for clock spins and charged call latency, ahead of performance work on the
//! clock: exactly when a run of clock reads becomes a spin, exactly how far each step of a spin
//! moves time, and exactly what each non-blocking call costs.
//!
//! The rules pinned: 63 reads in a row hold still, the 64th moves the clock 1 µs, as do the 65,535
//! reads after it, and every read after those moves it `min(max(spun / 64, 1 µs), 1 s)`, where
//! `spun` is the time since the spin was caught;
//! any other hooked call ends the spin and starts the count again; a step never jumps a pending
//! timer but lands 1 ns short of it and then 1 ns past it; a paused or executive-driven clock
//! never moves under a spin; a call that returns without blocking costs exactly 1 µs, and inside
//! an executive's grant never more than the grant's horizon. Readings come from
//! `snare::sched::now()`, which is not itself a hooked call and so does not end a spin.

use std::net::UdpSocket;
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use snare::sched::{self, ExecutiveConfig, Grant};

#[path = "support/landing.rs"]
mod landing;

const US: u64 = 1_000;

/// Sim time in nanoseconds, read without ticking the clock.
fn ns() -> u64 {
    sched::now().as_nanos() as u64
}

/// A sim to build, with its name for messages.
type NamedSim = (&'static str, fn() -> Sim);

fn sims() -> [NamedSim; 2] {
    [
        ("discrete", Sim::new as fn() -> Sim),
        ("deterministic", || {
            Sim::builder().deterministic().seed(3).build()
        }),
    ]
}

/// `n` reads of the clock through the hooked `Instant::now`.
fn reads(n: usize) {
    for _ in 0..n {
        std::hint::black_box(Instant::now());
    }
}

/// A hooked call that is neither a clock read nor a yield, and returns without being charged.
fn other_call(sock: &UdpSocket) {
    sock.local_addr().unwrap();
}

/// Reads of a caught spin, counted from the one that catches it, that each move the clock 1 µs.
const EVEN_READS: usize = 1 << 16;

/// The readings after each of `n` reads of a lone spin caught at `origin`, as the step rule gives
/// them: still for 63 reads, 1 µs for each of the next [`EVEN_READS`], then each read moves
/// `min(max((now - origin) / 64, 1 µs), 1 s)`.
fn spin_model(origin: u64, n: usize) -> Vec<u64> {
    let mut now = origin;
    (1..=n)
        .map(|read| {
            if read >= 64 + EVEN_READS {
                now = now.saturating_add(((now - origin) / 64).clamp(US, 1_000_000_000));
            } else if read >= 64 {
                now += US;
            }
            now
        })
        .collect()
}

#[test]
fn the_sixty_fourth_read_in_a_row_is_the_first_to_move_the_clock() {
    for (name, sim) in sims() {
        let seen = sim().run(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            [63, 64, 65, 128]
                .into_iter()
                .map(|n| {
                    other_call(&sock);
                    let before = ns();
                    reads(n);
                    ns() - before
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(seen, vec![0, US, 2 * US, 65 * US], "{name}");
    }
}

#[test]
fn reads_split_by_other_calls_never_add_up_to_a_spin() {
    for (name, sim) in sims() {
        let at = sim().run(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            for _ in 0..200 {
                reads(63);
                other_call(&sock);
            }
            ns()
        });
        assert_eq!(at, 0, "{name}");
    }
}

/// Every reading of a spin of 68,000 reads, exactly as the step rule gives it: 1 µs steps for the
/// first 65,536 reads of the caught spin, then steps of 1/64 of its age, capped at one second.
#[test]
fn a_lone_spin_steps_exactly_by_the_rule() {
    const READS: usize = 68_000;
    let expected = spin_model(0, READS);
    assert_eq!(expected[63], US);
    assert_eq!(expected[127], 65 * US);
    assert_eq!(expected[63 + EVEN_READS - 1], EVEN_READS as u64 * US);
    assert_eq!(
        expected[63 + EVEN_READS],
        (EVEN_READS as u64 + EVEN_READS as u64 / 64) * US
    );
    assert!(expected[READS - 1] < 3_600_000_000_000);
    for (name, sim) in sims() {
        let seen = sim().run(|| {
            (0..READS)
                .map(|_| {
                    reads(1);
                    ns()
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(seen, expected, "{name}");
    }
}

/// A spin caught later steps from where it was caught, not from zero.
#[test]
fn a_spin_steps_from_where_it_was_caught() {
    for (name, sim) in sims() {
        let seen = sim().run(|| {
            thread::sleep(Duration::from_secs(1));
            (0..300)
                .map(|_| {
                    reads(1);
                    ns()
                })
                .collect::<Vec<_>>()
        });
        assert_eq!(
            seen,
            spin_model(landing::past(1_000_000_000), 300),
            "{name}"
        );
    }
}

/// A spin passing a sleeper's deadline lands 1 ns short of it, then just past it, where the
/// sleeper wakes; the distinct readings the spinner sees are fixed. On the plain clock the spinner
/// may read the landing past the deadline more than once while the woken sleeper gets to run, so
/// repeats are folded.
#[test]
fn a_spin_lands_just_short_of_then_just_past_a_timer() {
    for (name, sim) in sims() {
        let (spun, woke) = sim().run(|| {
            let sleeper = thread::spawn(|| {
                thread::sleep(Duration::from_nanos(50 * US));
                ns()
            });
            let mut spun = Vec::new();
            while ns() < 80 * US {
                reads(1);
                spun.push(ns());
            }
            spun.dedup();
            (spun, sleeper.join().unwrap())
        });
        let past = landing::past(50 * US);
        assert_eq!(woke, past, "{name}");
        let near: Vec<u64> = spun
            .iter()
            .copied()
            .filter(|&v| (48 * US..=52 * US).contains(&v))
            .collect();
        assert_eq!(
            near,
            vec![48 * US, 49 * US, 50 * US - 1, past, past + US],
            "{name}: {spun:?}"
        );
    }
}

#[test]
fn a_spin_never_moves_a_paused_clock() {
    for (name, sim) in sims() {
        let sim = sim();
        sim.pause_time();
        let at = sim.run(|| {
            reads(1_000);
            ns()
        });
        assert_eq!(at, 0, "{name}");
        sim.resume_time();
        let at = sim.run(|| {
            reads(64);
            ns()
        });
        assert_eq!(at, US, "{name}: the spin moves the resumed clock");
    }
}

/// Fails `n` non-blocking receives on an empty socket, each of which is charged.
fn empty_receives(sock: &UdpSocket, n: usize) {
    let mut buf = [0u8; 4];
    for _ in 0..n {
        let err = sock.recv_from(&mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::WouldBlock);
    }
}

#[test]
fn each_call_that_returns_without_blocking_costs_one_microsecond() {
    for (name, sim) in sims() {
        let seen = sim().run(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            let mut seen = vec![ns()];
            for n in [1, 9, 990] {
                empty_receives(&sock, n);
                seen.push(ns());
            }
            seen
        });
        assert_eq!(seen, vec![0, US, 10 * US, 1_000 * US], "{name}");
    }
}

/// Charges between clock reads end the spin each time: a busy poll that reads the clock between
/// receives moves only by the charges.
#[test]
fn charges_between_reads_end_the_spin() {
    for (name, sim) in sims() {
        let at = sim().run(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            for _ in 0..100 {
                reads(63);
                empty_receives(&sock, 1);
            }
            ns()
        });
        assert_eq!(at, 100 * US, "{name}");
    }
}

/// Under an executive a spin never moves the clock, charges crawl it exactly 1 µs per call up to
/// the grant's horizon and no further, and once the executive lets go spins and charges move it as
/// before, from where it was left.
#[test]
fn spins_and_charges_under_an_executive_grant() {
    for (name, sim) in sims() {
        let sim = sim();
        let exec = sim.executive(ExecutiveConfig::default()).unwrap();
        exec.grant(Grant {
            anchor_v: Duration::ZERO,
            anchor_wall: snare::real(Instant::now),
            rate: 0.0,
            horizon: Duration::from_nanos(25 * US + 500),
        });
        let seen = sim.run(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            let mut seen = Vec::new();
            reads(1_000);
            seen.push(ns());
            empty_receives(&sock, 5);
            seen.push(ns());
            reads(1_000);
            seen.push(ns());
            empty_receives(&sock, 20);
            seen.push(ns());
            empty_receives(&sock, 1);
            seen.push(ns());
            empty_receives(&sock, 100);
            seen.push(ns());
            seen
        });
        assert_eq!(
            seen,
            vec![0, 5 * US, 5 * US, 25 * US, 25 * US + 500, 25 * US + 500],
            "{name}"
        );
        assert_eq!(exec.now(), Duration::from_nanos(25 * US + 500), "{name}");
        drop(exec);
        let after = sim.run(|| {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_nonblocking(true).unwrap();
            empty_receives(&sock, 1);
            let charged = ns();
            reads(64);
            (charged, ns())
        });
        assert_eq!(
            after,
            (26 * US + 500, 27 * US + 500),
            "{name}: back on the base clock"
        );
    }
}

/// Two threads spinning together each step the shared clock: neither reads time going back, and
/// the replay under the schedule is exact.
#[test]
fn two_spinners_see_monotonic_readings_and_replay() {
    let run = |sim: Sim| {
        sim.run(|| {
            let spinners: Vec<_> = (0..2)
                .map(|_| {
                    thread::spawn(|| {
                        let mut seen = Vec::new();
                        while ns() < 200 * US {
                            reads(1);
                            seen.push(ns());
                        }
                        seen.push(ns());
                        seen
                    })
                })
                .collect();
            spinners
                .into_iter()
                .map(|h| h.join().unwrap())
                .collect::<Vec<_>>()
        })
    };
    for (name, sim) in sims() {
        for seen in run(sim()) {
            assert!(seen.windows(2).all(|w| w[0] <= w[1]), "{name}: {seen:?}");
            assert!(*seen.last().unwrap() >= 200 * US, "{name}");
        }
    }
    let det = || run(Sim::builder().deterministic().seed(3).build());
    assert_eq!(det(), det(), "replays under the schedule");
}
