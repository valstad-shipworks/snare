use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use snare::sched::{self, DRIVEN_ORIGIN, DRIVEN_WALL_EPOCH, Driver, DriverConfig, attach_driver};
use snare::time::SystemTime;
use snare::{pause_time, register_test, set_time_value, time_value};

static SERIAL: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn attach() -> Driver {
    register_test();
    sched::mark_driver_thread();
    attach_driver(DriverConfig {
        seed: 7,
        accounting: true,
        audit: false,
    })
    .unwrap()
}

fn wall_now() -> Duration {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
}

fn assert_fixed_epoch(driver: &Driver) {
    assert_eq!(driver.now(), Duration::from_secs(1));
    assert_eq!(time_value(), Duration::from_secs(1));
    assert_eq!(wall_now(), Duration::from_secs(1_767_225_600));

    let t = Duration::from_nanos(1_000_000_001);
    driver.enter_timestamp(t);
    assert_eq!(wall_now(), Duration::from_nanos(1_767_225_600_000_000_001));
    driver.leave_timestamp(t);
    assert_eq!(time_value(), t);
    assert_eq!(wall_now(), Duration::from_nanos(1_767_225_600_000_000_001));
}

#[test]
fn attach_starts_at_the_fixed_origin_and_wall_epoch() {
    let _s = serial();
    assert_eq!(DRIVEN_ORIGIN, Duration::from_secs(1));
    assert_eq!(DRIVEN_WALL_EPOCH, Duration::from_secs(1_767_225_600));
    let driver = attach();
    assert_fixed_epoch(&driver);
}

#[test]
fn every_attach_on_a_fresh_slot_lands_on_the_same_instant() {
    let _s = serial();
    for _ in 0..3 {
        std::thread::sleep(Duration::from_micros(37));
        let driver = attach();
        assert_fixed_epoch(&driver);
    }
}

#[test]
fn a_clock_past_the_origin_moves_to_the_next_whole_second() {
    let _s = serial();
    register_test();
    pause_time();
    set_time_value(Duration::from_nanos(2_500_000_123));
    sched::mark_driver_thread();
    let driver = attach_driver(DriverConfig::default()).unwrap();
    assert_eq!(driver.now(), Duration::from_secs(3));
    assert_eq!(wall_now(), Duration::from_secs(1_767_225_600));
}
