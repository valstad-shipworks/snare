#![cfg(unix)]

use std::sync::mpsc;
use std::time::Duration;

#[test]
fn a_real_sigint_reaches_the_handler() {
    #[cfg(feature = "shim")]
    let driver = {
        snare::register_test();
        snare::sched::mark_driver_thread();
        snare::sched::attach_driver(snare::sched::DriverConfig {
            seed: 1,
            accounting: true,
            audit: true,
        })
        .unwrap()
    };
    let (tx, rx) = mpsc::channel();
    snare::ctrlc::set_handler(move || {
        let _ = tx.send(std::thread::current().name().map(String::from));
    })
    .unwrap();
    assert!(matches!(
        snare::ctrlc::try_set_handler(|| {}),
        Err(snare::ctrlc::Error::MultipleHandlers)
    ));
    #[cfg(feature = "shim")]
    {
        let start = std::time::Instant::now();
        while !driver.quiescence().quiescent {
            assert!(start.elapsed() < Duration::from_secs(5));
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    let status = std::process::Command::new("kill")
        .args(["-INT", &std::process::id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());

    let name = rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(name.as_deref(), Some("ctrl-c"));
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());

    #[cfg(feature = "shim")]
    {
        let audit = driver.audit();
        assert_eq!(audit.stray_wakes, 0);
        assert_eq!(audit.total_violations, 0, "{:?}", audit.violations);
        assert!(
            audit
                .class_effects
                .iter()
                .any(|e| e.class == snare::sched::ThreadClass::Background)
        );
    }
}
