//! Monotonic time never goes backwards: not on one thread, not across threads that synchronize,
//! and not between the different monotonic clock ids, whatever moves the clock meanwhile — time
//! skips, rate changes, pauses and resumes, advances and set values, from inside the sim or out.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use snare::{Sim, TimeHandle};

/// The highest reading any thread has published, per source. A reader loads it before reading its
/// clock, so its read happens after every read that published a value it saw.
struct Published {
    base: Instant,
    instant: AtomicU64,
    #[cfg(unix)]
    ids: AtomicU64,
    #[cfg(target_os = "macos")]
    mach: AtomicU64,
    #[cfg(windows)]
    ticks: AtomicU64,
}

struct Last {
    instant: u64,
    #[cfg(unix)]
    ids: u64,
    #[cfg(target_os = "macos")]
    mach: u64,
    #[cfg(windows)]
    ticks: u64,
}

fn observe(what: &str, slot: &AtomicU64, last: &mut u64, read: impl FnOnce() -> u64) {
    let seen = slot.load(Ordering::Acquire);
    let now = read();
    assert!(
        now >= *last,
        "{what} went backwards on one thread: {} -> {now}",
        *last
    );
    assert!(
        now >= seen,
        "{what} went backwards across threads: {seen} was published, then {now} read"
    );
    *last = now;
    slot.fetch_max(now, Ordering::Release);
}

#[cfg(target_os = "linux")]
const CLOCK_IDS: &[libc::clockid_t] = &[
    libc::CLOCK_MONOTONIC,
    libc::CLOCK_MONOTONIC_RAW,
    libc::CLOCK_MONOTONIC_COARSE,
    libc::CLOCK_BOOTTIME,
];

#[cfg(target_os = "macos")]
const CLOCK_IDS: &[libc::clockid_t] = &[
    libc::CLOCK_MONOTONIC,
    libc::CLOCK_MONOTONIC_RAW,
    libc::CLOCK_UPTIME_RAW,
];

#[cfg(unix)]
fn clock_nanos(id: libc::clockid_t) -> u64 {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    assert_eq!(unsafe { libc::clock_gettime(id, &mut ts) }, 0);
    ts.tv_sec as u64 * 1_000_000_000 + ts.tv_nsec as u64
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

impl Published {
    fn new() -> Arc<Self> {
        Arc::new(Published {
            base: Instant::now(),
            instant: AtomicU64::new(0),
            #[cfg(unix)]
            ids: AtomicU64::new(0),
            #[cfg(target_os = "macos")]
            mach: AtomicU64::new(0),
            #[cfg(windows)]
            ticks: AtomicU64::new(0),
        })
    }

    fn last(&self) -> Last {
        Last {
            instant: 0,
            #[cfg(unix)]
            ids: 0,
            #[cfg(target_os = "macos")]
            mach: 0,
            #[cfg(windows)]
            ticks: 0,
        }
    }

    fn read_all(&self, last: &mut Last, round: usize) {
        observe("Instant", &self.instant, &mut last.instant, || {
            let since = Instant::now()
                .checked_duration_since(self.base)
                .expect("Instant went back before a reading taken earlier");
            since.as_nanos() as u64
        });
        #[cfg(unix)]
        {
            let id = CLOCK_IDS[round % CLOCK_IDS.len()];
            observe("the monotonic clock ids", &self.ids, &mut last.ids, || {
                clock_nanos(id)
            });
        }
        #[cfg(target_os = "macos")]
        observe(
            "mach_absolute_time",
            &self.mach,
            &mut last.mach,
            || unsafe { mach_absolute_time() },
        );
        #[cfg(windows)]
        observe("GetTickCount64", &self.ticks, &mut last.ticks, || unsafe {
            windows_sys::Win32::System::SystemInformation::GetTickCount64()
        });
        let _ = round;
    }
}

/// Runs `readers` threads inside `sim`, each reading every monotonic source `rounds` times and
/// checking it against itself and every other reader, sleeping now and then so a discrete clock
/// moves, while `control` moves the clock from a thread outside the sim until they finish. Reader
/// 0 also advances the clock itself from inside.
fn hammer(sim: &Sim, rounds: usize, control: impl Fn(&TimeHandle, u64) + Send + 'static) {
    let time = sim.time();
    let stop = Arc::new(AtomicBool::new(false));
    let controller = {
        let stop = stop.clone();
        let time = time.clone();
        std::thread::spawn(move || {
            let mut step = 0;
            while !stop.load(Ordering::Acquire) {
                control(&time, step);
                step += 1;
                std::thread::yield_now();
            }
            time.resume();
        })
    };
    sim.run(|| {
        let published = Published::new();
        let readers: Vec<_> = (0..4)
            .map(|reader| {
                let published = published.clone();
                std::thread::spawn(move || {
                    let mut last = published.last();
                    for round in 0..rounds {
                        published.read_all(&mut last, round);
                        if round % 64 == 63 {
                            std::thread::sleep(Duration::from_micros(10 + reader as u64));
                        }
                        if reader == 0 && round % 256 == 255 {
                            snare::time().advance(Duration::from_micros(3));
                        }
                        if round % 16 == 0 {
                            std::thread::yield_now();
                        }
                    }
                })
            })
            .collect();
        let mut last = published.last();
        for round in 0..rounds / 4 {
            published.read_all(&mut last, round);
        }
        for reader in readers {
            reader.join().unwrap();
        }
    });
    stop.store(true, Ordering::Release);
    controller.join().unwrap();
}

/// Every way a clock can be moved, in turn.
fn every_move(time: &TimeHandle, step: u64) {
    match step % 12 {
        0 => time.pause(),
        1 => time.advance(Duration::from_micros(500)),
        2 => time.resume(),
        3 => time.set_rate(1_000.0),
        4 => time.pause(),
        5 => time.set_value(time.value() + Duration::from_millis(50)),
        6 => time.set_rate(1.0),
        7 => time.set_rate(f64::INFINITY),
        8 => time.pause(),
        9 => time.set_rate(1e6),
        10 => time.resume(),
        _ => time.set_rate(f64::INFINITY),
    }
}

/// The moves a deterministic sim allows: no real-time rates.
fn virtual_moves(time: &TimeHandle, step: u64) {
    match step % 6 {
        0 => time.pause(),
        1 => time.advance(Duration::from_micros(500)),
        2 => time.resume(),
        3 => time.pause(),
        4 => time.set_value(time.value() + Duration::from_millis(50)),
        _ => time.set_rate(f64::INFINITY),
    }
}

const ROUNDS: usize = 50_000;

#[test]
fn discrete_clock_under_every_move() {
    hammer(&Sim::new(), ROUNDS, every_move);
}

#[test]
fn scaled_clock_under_every_move() {
    hammer(&Sim::builder().time_rate(1.0).build(), ROUNDS, every_move);
}

#[test]
fn wall_clock_with_a_rate_under_every_move() {
    hammer(
        &Sim::builder().wall_clock().time_rate(10.0).build(),
        ROUNDS,
        every_move,
    );
}

#[test]
fn deterministic_clock_under_every_move() {
    hammer(
        &Sim::builder().deterministic().build(),
        ROUNDS,
        virtual_moves,
    );
}

#[test]
fn untouched_discrete_clock() {
    hammer(&Sim::new(), ROUNDS, |_, _| {
        std::thread::sleep(Duration::from_millis(1))
    });
}

#[cfg(windows)]
#[test]
fn controllable_wall_clock_under_every_move() {
    hammer(
        &Sim::builder().wall_clock().time_rate(1.0).build(),
        ROUNDS,
        every_move,
    );
}

#[cfg(unix)]
#[test]
fn simhost_clock_under_every_move() {
    let host = snare::HostProfile::new().build();
    hammer(&Sim::builder().host(host).build(), ROUNDS, every_move);
}

#[cfg(unix)]
#[test]
fn simhost_as_fast_as_possible_clock_under_every_move() {
    let host = snare::HostProfile::new().build();
    hammer(
        &Sim::builder().host(host).wall_clock().build(),
        ROUNDS,
        every_move,
    );
}

#[cfg(unix)]
#[test]
fn simhost_deterministic_clock_under_every_move() {
    let host = snare::HostProfile::new().build();
    hammer(
        &Sim::builder().host(host).deterministic().build(),
        ROUNDS,
        virtual_moves,
    );
}

#[test]
#[should_panic(expected = "time is monotonic")]
fn setting_the_clock_back_panics() {
    let sim = Sim::new();
    sim.advance_time(Duration::from_secs(5));
    sim.set_time_value(Duration::from_secs(1));
}

#[test]
fn a_rejected_set_leaves_the_clock_alone() {
    let sim = Sim::new();
    sim.set_time_value(Duration::from_secs(5));
    let time = sim.time();
    let refused = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        time.set_value(Duration::from_secs(1))
    }));
    assert!(refused.is_err());
    assert_eq!(sim.time_value(), Duration::from_secs(5));
}

/// Every absolute monotonic reading the code under test can make, as raw values.
fn absolute_readings() -> Vec<String> {
    let mut out = vec![format!("{:?}", Instant::now())];
    #[cfg(unix)]
    out.extend(CLOCK_IDS.iter().map(|&id| clock_nanos(id).to_string()));
    #[cfg(target_os = "macos")]
    out.push(unsafe { mach_absolute_time() }.to_string());
    #[cfg(windows)]
    {
        let mut count = 0i64;
        unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut count) };
        out.push(count.to_string());
        out.push(
            unsafe { windows_sys::Win32::System::SystemInformation::GetTickCount64() }.to_string(),
        );
    }
    out
}

fn replay(sim: Sim) -> Vec<Vec<String>> {
    sim.run(|| {
        let first = absolute_readings();
        std::thread::sleep(Duration::from_millis(1_500));
        let after_sleep = std::thread::spawn(absolute_readings).join().unwrap();
        vec![first, after_sleep]
    })
}

#[test]
fn replays_read_identical_absolute_monotonic_values() {
    let fixed = || Sim::builder().fixed_epoch().build();
    let first = replay(fixed());
    assert_eq!(
        replay(fixed()),
        first,
        "a sim on the fixed epoch starts at a fixed instant"
    );
    #[cfg(unix)]
    assert!(
        first[0][1..1 + CLOCK_IDS.len()]
            .iter()
            .all(|v| v.parse::<u64>().unwrap() < 1_000_000_000),
        "the monotonic clock ids start at zero: {first:?}"
    );
    let det = || Sim::builder().deterministic().seed(11).build();
    let first_det = replay(det());
    assert_eq!(
        replay(det()),
        first_det,
        "a deterministic sim replays its instants"
    );
    assert_eq!(first_det, first, "and starts where every sim does");
}

#[test]
fn an_instant_kept_from_an_earlier_sim_is_never_ahead_of_a_later_one() {
    let kept = Sim::new().run(|| {
        std::thread::sleep(Duration::from_secs(3_600));
        Instant::now()
    });
    let second = Sim::new();
    second.run(|| {
        assert!(
            Instant::now() >= kept,
            "a plain sim continues the process's time"
        )
    });
    assert_eq!(second.time_value(), Duration::ZERO);
}

#[test]
fn an_instant_kept_from_an_earlier_sim_is_on_another_timeline_on_the_fixed_epoch() {
    let kept = Sim::new().run(|| {
        std::thread::sleep(Duration::from_secs(3_600));
        Instant::now()
    });
    let second = Sim::builder().fixed_epoch().build();
    second.run(|| {
        assert!(
            Instant::now() < kept,
            "a fixed-epoch sim starts its own timeline again"
        )
    });
    assert_eq!(second.time_value(), Duration::ZERO);
}

#[cfg(target_os = "linux")]
#[test]
fn a_delayed_datagram_is_never_stamped_after_the_clock() {
    const SO_TIMESTAMPING: libc::c_int = 37;
    const SOF_TIMESTAMPING_RX_SOFTWARE: u32 = 1 << 3;
    const SOF_TIMESTAMPING_SOFTWARE: u32 = 1 << 4;
    let host = snare::HostProfile::new().build();
    Sim::builder().host(host).wall_clock().build().run(|| {
        snare::set_udp_policy("127.0.0.1:9450", |p| p.latency = Duration::from_millis(30));
        let rx = std::net::UdpSocket::bind("127.0.0.1:9450").unwrap();
        let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let flags = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
        let rc = unsafe {
            libc::setsockopt(
                std::os::fd::AsRawFd::as_raw_fd(&rx),
                libc::SOL_SOCKET,
                SO_TIMESTAMPING,
                (&flags as *const u32).cast(),
                4,
            )
        };
        assert_eq!(rc, 0);
        tx.send_to(b"late", "127.0.0.1:9450").unwrap();
        let mut buf = [0u8; 16];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let mut control = [0u8; 128];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len();
        let got = loop {
            let got = unsafe { libc::recvmsg(std::os::fd::AsRawFd::as_raw_fd(&rx), &mut msg, 0) };
            if got >= 0 {
                break got;
            }
            snare::real(|| std::thread::sleep(Duration::from_millis(1)));
        };
        assert_eq!(got, 4);
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
        assert!(!cmsg.is_null());
        let stamp = unsafe { (libc::CMSG_DATA(cmsg) as *const libc::timespec).read_unaligned() };
        let stamp = stamp.tv_sec as u64 * 1_000_000_000 + stamp.tv_nsec as u64;
        let after = clock_nanos(libc::CLOCK_REALTIME);
        assert!(
            after >= stamp,
            "received at {stamp}, then the clock read {after}"
        );
    });
}

#[cfg(windows)]
#[test]
fn tick_count_follows_the_virtual_clock() {
    use windows_sys::Win32::System::SystemInformation::GetTickCount64;
    let real = snare::real(Instant::now);
    Sim::new().run(|| {
        let before = unsafe { GetTickCount64() };
        std::thread::sleep(Duration::from_secs(30));
        let after = unsafe { GetTickCount64() };
        assert!(after - before >= 30_000, "{before} -> {after}");
    });
    assert!(snare::real(|| real.elapsed()) < Duration::from_secs(30));
}

/// One executive move, in turn: grants (flowing, frozen, anchored behind the clock), freezes, jumps,
/// checked and unchecked timestamps (one stale), and, every so often, handing the clock back and
/// taking it again.
fn executive_move(exec: &mut Option<snare::sched::Executive>, sim: &Sim, step: u64, det: bool) {
    use snare::sched::{ExecutiveConfig, Grant};
    let Some(e) = exec.as_ref() else {
        *exec = Some(sim.executive(ExecutiveConfig::default()).unwrap());
        return;
    };
    let now = e.now();
    let real = snare::real(Instant::now);
    match step % 10 {
        0 => e.grant(Grant {
            anchor_v: now,
            anchor_wall: real,
            rate: if det { 0.0 } else { 1_000.0 },
            horizon: now + Duration::from_millis(3),
        }),
        1 => e.freeze(),
        2 => {
            let _ = e.jump_to(now + Duration::from_millis(1));
        }
        3 => e.grant(Grant {
            anchor_v: now.saturating_sub(Duration::from_millis(5)),
            anchor_wall: real,
            rate: if det { 0.0 } else { 1e6 },
            horizon: now + Duration::from_millis(2),
        }),
        4 => {
            let t = now + Duration::from_micros(300);
            if e.enter_timestamp_checked(t).is_ok() {
                e.leave_timestamp(t);
            }
        }
        5 => {
            let _ = e.jump_to(now + Duration::from_millis(2));
        }
        6 if !det => {
            let t = now + Duration::from_micros(700);
            e.enter_timestamp(t);
            e.leave_timestamp(t);
        }
        7 if !det => {
            let t = now.saturating_sub(Duration::from_millis(1));
            e.enter_timestamp(t);
            e.leave_timestamp(t);
        }
        9 => *exec = None,
        _ => {
            let _ = e.jump_to(now + Duration::from_micros(100));
        }
    }
}

/// Background readers hammer every monotonic source while an executive moves the clock from
/// outside every way it can, while a participant sleeping in steps gives its jumps somewhere to land.
fn hammer_executive(sim: &Sim, det: bool) {
    let done = Arc::new(AtomicBool::new(false));
    std::thread::scope(|s| {
        let controller = s.spawn(|| {
            let mut exec = None;
            let mut step = 0;
            while !done.load(Ordering::Acquire) {
                executive_move(&mut exec, sim, step, det);
                step += 1;
                std::thread::yield_now();
            }
        });
        struct Done<'a>(&'a AtomicBool);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }
        let _done = Done(&done);
        sim.run(|| {
            let published = Published::new();
            let ticker = std::thread::spawn({
                let done = done.clone();
                move || {
                    while !done.load(Ordering::Acquire) {
                        std::thread::sleep(Duration::from_micros(250));
                    }
                }
            });
            let readers: Vec<_> = (0..4)
                .map(|reader| {
                    let published = published.clone();
                    std::thread::spawn(move || {
                        snare::sched::mark_background("reader");
                        let mut last = published.last();
                        for round in 0..ROUNDS {
                            published.read_all(&mut last, round);
                            if round % 64 == 63 {
                                std::thread::sleep(Duration::from_micros(10 + reader as u64));
                            }
                        }
                    })
                })
                .collect();
            for reader in readers {
                reader.join().unwrap();
            }
            done.store(true, Ordering::Release);
            ticker.join().unwrap();
        });
        controller.join().unwrap();
    });
}

#[test]
fn executive_driven_clock_under_every_move() {
    hammer_executive(&Sim::new(), false);
}

#[test]
fn executive_driven_deterministic_clock_under_every_move() {
    hammer_executive(&Sim::builder().deterministic().build(), true);
}

#[cfg(unix)]
#[test]
fn executive_driven_simhost_clock_under_every_move() {
    let host = snare::HostProfile::new().build();
    hammer_executive(&Sim::builder().host(host).wall_clock().build(), false);
}

#[cfg(windows)]
#[test]
fn executive_driven_controllable_wall_clock_under_every_move() {
    hammer_executive(&Sim::builder().wall_clock().time_rate(1.0).build(), false);
}
