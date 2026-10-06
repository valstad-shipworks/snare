#![cfg(windows)]

#[path = "support/landing.rs"]
mod landing;

use std::io::{BufRead, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use snare::Sim;
use windows_sys::Win32::System::Threading::{Sleep, SleepEx};

const END: Duration = Duration::from_nanos(u64::MAX);
const CHILD_MODE: &str = "SNARE_STD_SLEEP_CHILD";

fn builder(deterministic: bool) -> snare::SimBuilder {
    if deterministic {
        Sim::builder().deterministic()
    } else {
        Sim::builder()
    }
}

fn longest_timer_duration() -> Duration {
    let intervals = i64::MAX as u64;
    Duration::new(
        intervals / 10_000_000,
        (intervals % 10_000_000) as u32 * 100,
    )
}

#[test]
fn huge_finite_rust_sleeps_saturate_instead_of_becoming_infinite() {
    let longest = longest_timer_duration();
    let durations = [
        END,
        longest,
        longest + Duration::from_nanos(100),
        Duration::from_secs(u64::MAX),
        Duration::MAX,
    ];
    for deterministic in [false, true] {
        for start in [Duration::ZERO, Duration::from_secs(3)] {
            for duration in durations {
                let sim = builder(deterministic).build();
                sim.set_time_value(start);
                sim.run(|| thread::sleep(duration));
                let expected = if duration == END && start.is_zero() {
                    Duration::from_nanos(landing::past(u64::MAX / 100 * 100))
                } else {
                    END
                };
                assert_eq!(
                    sim.time_value(),
                    expected,
                    "{deterministic}, {start:?}, {duration:?}"
                );
            }
        }
    }
}

#[test]
fn a_paused_huge_rust_sleep_requires_its_finite_deadline() {
    for deterministic in [false, true] {
        let sim = Arc::new(builder(deterministic).build());
        sim.pause_time();
        let executive = sim.executive(Default::default()).unwrap();
        let controller = snare::real(|| {
            thread::spawn(move || {
                let start = Instant::now();
                loop {
                    let status = executive.quiescence();
                    if status.quiescent && status.blocked == 1 {
                        assert_eq!(status.next_deadline, Some(END));
                        break;
                    }
                    assert!(start.elapsed() < Duration::from_secs(10), "{status:?}");
                    thread::yield_now();
                }
                assert!(executive.jump_to(END - Duration::from_secs(1)).is_ok());
                let settled = Instant::now();
                loop {
                    let status = executive.quiescence();
                    if status.quiescent {
                        assert_eq!(status.blocked, 1);
                        assert_eq!(status.next_deadline, Some(END));
                        break;
                    }
                    assert!(settled.elapsed() < Duration::from_secs(10), "{status:?}");
                    thread::yield_now();
                }
                assert!(executive.jump_to(END).is_ok());
            })
        });
        sim.run(|| thread::sleep(Duration::MAX));
        controller.join().unwrap();
        assert_eq!(sim.time_value(), END);
    }
}

#[test]
fn the_largest_finite_native_sleep_keeps_its_millisecond_duration() {
    let duration = Duration::from_millis(u64::from(u32::MAX - 1));
    for deterministic in [false, true] {
        let sim = builder(deterministic).build();
        sim.run(|| unsafe { Sleep(u32::MAX - 1) });
        assert_eq!(
            sim.time_value(),
            Duration::from_nanos(landing::past(duration.as_nanos() as u64))
        );
    }
}

fn marker(value: &str) {
    snare::real(|| {
        let mut stdout = std::io::stdout().lock();
        writeln!(stdout, "{value}").unwrap();
        stdout.flush().unwrap();
    });
}

#[test]
fn infinite_sleep_child() {
    let Ok(mode) = std::env::var(CHILD_MODE) else {
        return;
    };
    let deterministic = mode.starts_with("det-");
    let native = mode.starts_with("native-");
    let extended = mode.ends_with("ex");
    let rust = mode.ends_with("rust");
    let sim = Arc::new(builder(deterministic).build());
    sim.pause_time();
    let controller_sim = sim.clone();
    let _controller = snare::real(|| {
        thread::spawn(move || {
            let mut input = String::new();
            std::io::stdin().read_line(&mut input).unwrap();
            assert_eq!(input.trim(), "ADVANCE");
            controller_sim.set_time_value(END);
            marker("SNARE_ADVANCED");
        })
    });
    let run = || {
        marker("SNARE_READY");
        let sleep = || unsafe {
            if rust {
                thread::sleep(Duration::MAX);
            } else if extended {
                assert_eq!(SleepEx(u32::MAX, 0), 0);
            } else {
                Sleep(u32::MAX);
            }
        };
        if native {
            snare::real(sleep)
        } else {
            sleep()
        }
        panic!("native infinite sleep returned");
    };
    if mode == "outside-rust" {
        run();
    } else {
        sim.run(run);
    }
}

struct RunningChild(Child);

impl Drop for RunningChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

fn wait_for_marker(output: &mpsc::Receiver<String>, expected: &str) {
    let start = Instant::now();
    loop {
        let remaining = Duration::from_secs(10).saturating_sub(start.elapsed());
        let line = output
            .recv_timeout(remaining)
            .unwrap_or_else(|error| panic!("missing {expected}: {error}"));
        if line.contains(expected) {
            return;
        }
    }
}

#[test]
fn genuine_native_infinite_sleeps_do_not_end_at_the_virtual_clock_limit() {
    for mode in [
        "native-sleep",
        "native-ex",
        "plain-sleep",
        "plain-ex",
        "det-sleep",
        "det-ex",
        "native-rust",
        "outside-rust",
    ] {
        let mut child = RunningChild(
            Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "infinite_sleep_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(CHILD_MODE, mode)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let stdout = child.0.stdout.take().unwrap();
        let (sender, output) = mpsc::channel();
        let reader = thread::spawn(move || {
            for line in std::io::BufReader::new(stdout).lines() {
                if sender.send(line.unwrap()).is_err() {
                    break;
                }
            }
        });
        wait_for_marker(&output, "SNARE_READY");
        writeln!(child.0.stdin.as_mut().unwrap(), "ADVANCE").unwrap();
        child.0.stdin.as_mut().unwrap().flush().unwrap();
        wait_for_marker(&output, "SNARE_ADVANCED");
        let observed = Instant::now();
        while observed.elapsed() < Duration::from_millis(250) {
            assert!(
                child.0.try_wait().unwrap().is_none(),
                "{mode} returned after the clock advanced"
            );
            thread::sleep(Duration::from_millis(5));
        }
        child.0.kill().unwrap();
        child.0.wait().unwrap();
        drop(output);
        reader.join().unwrap();
    }
}
