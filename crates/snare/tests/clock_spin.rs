//! Clock spins: a thread that waits on time by polling the clock, with or without yielding, and
//! no other hooked call in between, moves a discrete clock itself once the spin is caught, in
//! growing steps that never jump a pending timer, so the spin ends quickly in real time, replays
//! exactly, and leaves every other thread's wake-ups in their order. Isolated reads still hold
//! still, a held clock stays held, and the real clock is untouched.

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use snare::{Bytes, Sim, SimBuilder, TesterAction, udp_tester};

const MS: Duration = Duration::from_millis(1);
const US: Duration = Duration::from_micros(1);

/// Real time a spin test may take; a few milliseconds is typical.
const REAL_BUDGET: Duration = Duration::from_secs(5);

/// How a spin waits between reads of the clock.
#[derive(Clone, Copy, Debug)]
enum Pause {
    /// Nothing: `while Instant::now() < deadline {}`.
    None,
    /// `std::thread::yield_now`.
    Yield,
    /// `std::hint::spin_loop`.
    Hint,
}

/// Spins until `deadline`.
fn spin_until(deadline: Instant, pause: Pause) {
    while Instant::now() < deadline {
        match pause {
            Pause::None => {}
            Pause::Yield => thread::yield_now(),
            Pause::Hint => std::hint::spin_loop(),
        }
    }
}

/// The virtual time a spin of `wait` took, and the real time the run took.
fn spin_once(builder: SimBuilder, wait: Duration, pause: Pause) -> (Duration, Duration) {
    let real = Instant::now();
    let spun = builder.build().run(|| {
        let start = Instant::now();
        spin_until(start + wait, pause);
        start.elapsed()
    });
    (spun, real.elapsed())
}

/// The bound a spin of `wait` overshoots by, as read back by one more read after it: two steps,
/// each 1/64 of the spin or one microsecond.
fn overshoot(wait: Duration) -> Duration {
    2 * (wait / 64).max(US)
}

fn assert_spin_ends(builder: fn() -> SimBuilder, wait: Duration, pause: Pause) {
    let (spun, real) = spin_once(builder(), wait, pause);
    assert!(spun >= wait, "{pause:?}: spun {spun:?}, short of {wait:?}");
    assert!(
        spun <= wait + overshoot(wait),
        "{pause:?}: spun {spun:?} for {wait:?}, past the step bound"
    );
    assert!(real < REAL_BUDGET, "{pause:?}: took {real:?} of real time");
    assert_eq!(
        spin_once(builder(), wait, pause).0,
        spun,
        "{pause:?}: a spin replays exactly"
    );
}

#[test]
fn deadline_spin_ends_on_the_discrete_clock() {
    for pause in [Pause::None, Pause::Yield, Pause::Hint] {
        for wait in [5 * MS, Duration::from_secs(3600)] {
            assert_spin_ends(Sim::builder, wait, pause);
        }
    }
}

#[test]
fn deadline_spin_ends_under_deterministic() {
    for pause in [Pause::None, Pause::Yield, Pause::Hint] {
        for wait in [5 * MS, Duration::from_secs(3600)] {
            assert_spin_ends(|| Sim::builder().deterministic(), wait, pause);
        }
    }
}

#[test]
fn spin_sleep_sleeps_on_virtual_time() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        for strategy in [
            spin_sleep::SpinStrategy::YieldThread,
            spin_sleep::SpinStrategy::SpinLoopHint,
        ] {
            let real = Instant::now();
            let elapsed = builder().build().run(|| {
                let start = Instant::now();
                spin_sleep::SpinSleeper::new(1_000_000)
                    .with_spin_strategy(strategy)
                    .sleep(5 * MS);
                start.elapsed()
            });
            assert!(elapsed >= 5 * MS, "{strategy:?}: slept {elapsed:?}");
            assert!(
                elapsed <= 5 * MS + overshoot(MS),
                "{strategy:?}: slept {elapsed:?}"
            );
            assert!(
                real.elapsed() < REAL_BUDGET,
                "{strategy:?}: {:?}",
                real.elapsed()
            );
        }
    }
}

/// Threads interleaving on the clock: a spinner waiting out deadlines by polling, a sleeper, a
/// UDP tester ticking on a period and a reader of its datagrams. Returns what each logged, with
/// the virtual time since the start.
fn interleave(builder: SimBuilder, pause: Pause) -> Vec<(&'static str, Duration)> {
    let log: Arc<Mutex<Vec<(&'static str, Duration)>>> = Arc::default();
    builder.build().run(|| {
        let origin = Instant::now();
        let note = {
            let log = log.clone();
            move |what| log.lock().unwrap().push((what, origin.elapsed()))
        };
        let reader = std::net::UdpSocket::bind("127.0.0.1:4400").unwrap();
        let tester = udp_tester::<Bytes>("127.0.0.5:4401")
            .with_cyclic_action(2500 * US, || TesterAction::Send(Bytes(b"tick".to_vec())))
            .until_after(8 * MS);
        reader.send_to(b"hello", "127.0.0.5:4401").unwrap();
        let spinner = thread::spawn({
            let note = note.clone();
            move || {
                for (at, what) in [(3000, "spin 3.0"), (5500, "spin 5.5"), (7000, "spin 7.0")] {
                    spin_until(origin + at * US, pause);
                    note(what);
                }
            }
        });
        let sleeper = thread::spawn({
            let note = note.clone();
            move || {
                for (at, what) in [
                    (1500, "sleep 1.5"),
                    (4000, "sleep 4.0"),
                    (6500, "sleep 6.5"),
                ] {
                    thread::sleep((origin + at * US).saturating_duration_since(Instant::now()));
                    note(what);
                }
            }
        });
        let ticks = thread::spawn(move || {
            let mut buf = [0u8; 16];
            for _ in 0..3 {
                note(match reader.recv_from(&mut buf) {
                    Ok(_) => "tick",
                    Err(_) => "no tick",
                });
            }
        });
        snare::run_testers!(tester);
        for t in [spinner, sleeper, ticks] {
            t.join().unwrap();
        }
    });
    log.lock().unwrap().clone()
}

fn assert_interleaved(builder: fn() -> SimBuilder, pause: Pause) {
    let log = interleave(builder(), pause);
    let order: Vec<&str> = log.iter().map(|&(what, _)| what).collect();
    assert_eq!(
        order,
        [
            "sleep 1.5",
            "tick",
            "spin 3.0",
            "sleep 4.0",
            "tick",
            "spin 5.5",
            "sleep 6.5",
            "spin 7.0",
            "tick",
        ],
        "{pause:?}: {log:?}"
    );
    for &(what, at) in &log {
        if let Some(ms) = what.strip_prefix("spin ") {
            let due = Duration::from_secs_f64(ms.parse::<f64>().unwrap() / 1e3);
            assert!(
                at >= due && at <= due + overshoot(7 * MS),
                "{pause:?}: {what} at {at:?}: {log:?}"
            );
        }
    }
}

#[test]
fn spinner_sleeper_and_tester_keep_their_order() {
    for pause in [Pause::None, Pause::Yield] {
        assert_interleaved(Sim::builder, pause);
    }
}

#[test]
fn spinner_sleeper_and_tester_keep_their_order_under_deterministic() {
    for pause in [Pause::None, Pause::Yield] {
        assert_interleaved(|| Sim::builder().deterministic().seed(3), pause);
        let first = interleave(Sim::builder().deterministic().seed(3), pause);
        assert_eq!(
            interleave(Sim::builder().deterministic().seed(3), pause),
            first,
            "{pause:?}: replays exactly"
        );
    }
}

/// Two threads spinning on deadlines of their own at once both get there.
#[test]
fn two_spinners_both_finish() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        let ends = builder().build().run(|| {
            let origin = Instant::now();
            let spinners: Vec<_> = [(2 * MS, Pause::None), (3 * MS, Pause::Yield)]
                .into_iter()
                .map(|(wait, pause)| {
                    thread::spawn(move || {
                        spin_until(origin + wait, pause);
                        origin.elapsed()
                    })
                })
                .collect();
            spinners
                .into_iter()
                .map(|t| t.join().unwrap())
                .collect::<Vec<_>>()
        });
        assert!(ends[0] >= 2 * MS && ends[1] >= 3 * MS, "{ends:?}");
    }
}

/// A yield loop on a flag a sleeper sets still jumps straight to the sleeper's wake-up, alone or
/// beside a thread that only yields.
#[test]
fn yield_only_spin_jumps_to_the_wake_up() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        let at = builder().build().run(|| {
            let origin = Instant::now();
            let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let set = flag.clone();
            let sleeper = thread::spawn(move || {
                thread::sleep(Duration::from_secs(600));
                set.store(true, std::sync::atomic::Ordering::Release);
            });
            while !flag.load(std::sync::atomic::Ordering::Acquire) {
                thread::yield_now();
            }
            sleeper.join().unwrap();
            origin.elapsed()
        });
        assert!(at >= Duration::from_secs(600), "{at:?}");
        assert!(at < Duration::from_secs(600) + MS, "{at:?}");
    }
}

#[cfg(windows)]
#[test]
fn joining_an_exited_thread_ends_a_caught_yield_spin() {
    for deterministic in [false, true] {
        let sim = if deterministic {
            Sim::builder().deterministic().build()
        } else {
            Sim::new()
        };
        sim.run(|| {
            let origin = Instant::now();
            let child = std::thread::spawn(|| {});
            while !child.is_finished() {
                std::thread::yield_now();
            }
            for _ in 0..128 {
                std::thread::yield_now();
            }
            let before = snare::time().value();
            child.join().unwrap();
            assert_eq!(origin.elapsed(), before, "deterministic={deterministic}");
        });
    }
}

/// Reads that are not a spin hold still: back-to-back reads, a handful in a row, and reads with
/// other hooked calls between them.
#[test]
fn isolated_reads_hold_still() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        builder().build().run(|| {
            let first = Instant::now();
            for _ in 0..32 {
                assert_eq!(Instant::now(), first, "a few reads in a row hold still");
            }
            let sock = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            for _ in 0..1000 {
                let _ = sock.local_addr();
                let a = Instant::now();
                let b = Instant::now();
                assert_eq!(a, b, "reads between other hooked calls hold still");
            }
        });
    }
}

/// A spin on a paused clock moves nothing: it ends only once the clock is resumed from outside,
/// and then only by moving it itself.
#[test]
fn paused_clock_holds_a_spin() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        let sim = builder().build();
        sim.pause_time();
        let held = sim.time_value();
        let time = sim.time();
        let resumer = thread::spawn(move || {
            thread::sleep(100 * MS);
            let still = time.value();
            time.resume();
            still
        });
        let real = Instant::now();
        let spun = sim.run(|| {
            let start = Instant::now();
            spin_until(start + 2 * MS, Pause::None);
            start.elapsed()
        });
        assert_eq!(
            resumer.join().unwrap(),
            held,
            "the spin never moved a paused clock"
        );
        assert!(real.elapsed() >= 100 * MS, "the spin waited for the resume");
        assert!(
            spun >= 2 * MS && spun <= 2 * MS + overshoot(2 * MS),
            "{spun:?}"
        );
    }
}

/// Under the real clock a spin is a plain busy-wait on real time.
#[test]
fn wall_clock_spin_is_real() {
    let real = Instant::now();
    Sim::builder().wall_clock().build().run(|| {
        spin_until(Instant::now() + 20 * MS, Pause::None);
    });
    assert!(real.elapsed() >= 20 * MS);
}

/// A clock-polling yielder beside a thread sleeping far longer wakes at its own deadline: its
/// yields step toward it rather than jumping to the sleeper's wake-up.
#[test]
fn spin_sleep_beside_a_long_sleeper_wakes_on_time() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        let (woke, total) = builder().build().run(|| {
            let start = Instant::now();
            let peer = thread::spawn(|| thread::sleep(Duration::from_secs(1)));
            spin_sleep::SpinSleeper::new(1_000_000)
                .with_spin_strategy(spin_sleep::SpinStrategy::YieldThread)
                .sleep(5 * MS);
            let woke = start.elapsed();
            peer.join().unwrap();
            (woke, start.elapsed())
        });
        assert!(
            woke >= 5 * MS && woke <= 5 * MS + overshoot(MS),
            "woke at {woke:?}"
        );
        assert!(total >= Duration::from_secs(1), "{total:?}");
    }
}

/// crossbeam's `Backoff::snooze`, yielding while it waits on a flag a sleeper sets, gets there.
#[test]
fn backoff_snooze_waits_out_a_sleeper() {
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        let real = Instant::now();
        let at = builder().build().run(|| {
            let start = Instant::now();
            let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let set = flag.clone();
            let sleeper = thread::spawn(move || {
                thread::sleep(10 * MS);
                set.store(true, std::sync::atomic::Ordering::Release);
            });
            let backoff = crossbeam_utils::Backoff::new();
            while !flag.load(std::sync::atomic::Ordering::Acquire) {
                backoff.snooze();
            }
            sleeper.join().unwrap();
            start.elapsed()
        });
        assert!(at >= 10 * MS && at < 11 * MS, "{at:?}");
        assert!(real.elapsed() < REAL_BUDGET, "{:?}", real.elapsed());
    }
}

/// A rayon pool, whose idle workers yield before they sleep, finishes its work.
#[test]
fn rayon_pool_finishes() {
    use rayon::prelude::*;
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic()
    }] {
        let real = Instant::now();
        let sum = builder().build().run(|| {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(3)
                .build()
                .unwrap();
            pool.install(|| (0..100_000u64).into_par_iter().map(|x| x % 7).sum::<u64>())
        });
        assert_eq!(sum, (0..100_000u64).map(|x| x % 7).sum::<u64>());
        assert!(real.elapsed() < REAL_BUDGET * 4, "{:?}", real.elapsed());
    }
}

/// A consumer that reads the clock once per wake and parks between wakes, fed by a producer on a
/// 5 ms tick, sees every tick at its own instant: each park is a wait, which ends the spin its
/// clock reads began, so however many wakes it takes they never add up to a caught spin that
/// would step the consumer's clock ahead of the producer's ticks. `std::thread::park_timeout`
/// waits on a dispatch semaphore on macOS and a futex on Linux.
#[test]
fn reads_between_parks_are_not_a_spin() {
    use std::sync::atomic::{AtomicU64, Ordering};
    const TICKS: u64 = 100;
    for builder in [Sim::builder as fn() -> SimBuilder, || {
        Sim::builder().deterministic().seed(7)
    }] {
        let late = builder().build().run(|| {
            let seq = Arc::new(AtomicU64::new(0));
            let me = thread::current();
            let producer = {
                let seq = seq.clone();
                thread::spawn(move || {
                    let mut tick = Instant::now();
                    for _ in 0..TICKS {
                        tick += 5 * MS;
                        thread::sleep(tick.saturating_duration_since(Instant::now()));
                        seq.fetch_add(1, Ordering::SeqCst);
                        me.unpark();
                    }
                })
            };
            let start = Instant::now();
            let mut late = Vec::new();
            let mut seen = 0;
            while seen < TICKS {
                let now_seq = seq.load(Ordering::SeqCst);
                if now_seq > seen {
                    seen = now_seq;
                    let lag =
                        Instant::now().saturating_duration_since(start + 5 * MS * seen as u32);
                    if lag > 10 * US {
                        late.push((seen, lag));
                    }
                    continue;
                }
                thread::park_timeout(Duration::from_secs(1));
            }
            producer.join().unwrap();
            late
        });
        assert!(late.is_empty(), "ticks seen late: {late:?}");
    }
}
