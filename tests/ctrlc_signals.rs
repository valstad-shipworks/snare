//! Virtual signals and console events under each OS's semantics, with and
//! without `ctrlc-termination`.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use snare::ctrlc::{self, SignalDelivery, VirtualSignal};
use snare::{OsSemantics, register_test, set_os_semantics};

const ALL_OS: [OsSemantics; 3] = [OsSemantics::Linux, OsSemantics::MacOs, OsSemantics::Windows];

const SIGNALS: [VirtualSignal; 7] = [
    VirtualSignal::Interrupt,
    VirtualSignal::Terminate,
    VirtualSignal::Hangup,
    VirtualSignal::Break,
    VirtualSignal::Close,
    VirtualSignal::Logoff,
    VirtualSignal::Shutdown,
];

fn exists(os: OsSemantics, sig: VirtualSignal) -> bool {
    let unix = os != OsSemantics::Windows;
    match sig {
        VirtualSignal::Interrupt => true,
        VirtualSignal::Terminate | VirtualSignal::Hangup => unix,
        _ => !unix,
    }
}

fn counting_handler() -> Arc<AtomicU64> {
    let count = Arc::new(AtomicU64::new(0));
    let c = Arc::clone(&count);
    ctrlc::set_handler(move || {
        c.fetch_add(1, Ordering::SeqCst);
    })
    .unwrap();
    count
}

fn wait_for(count: &AtomicU64, n: u64) {
    let start = std::time::Instant::now();
    while count.load(Ordering::SeqCst) < n {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "handler ran {} of {n} times",
            count.load(Ordering::SeqCst)
        );
        std::thread::sleep(Duration::from_micros(200));
    }
}

#[test]
fn which_signals_exist() {
    for os in ALL_OS {
        register_test();
        set_os_semantics(os);
        for sig in SIGNALS {
            let expected = if exists(os, sig) {
                SignalDelivery::DefaultAction
            } else {
                SignalDelivery::Unavailable
            };
            assert_eq!(ctrlc::raise_signal(sig), expected, "{os} {sig:?}");
        }
        assert!(!ctrlc::raise(), "{os}: no handler");
    }
}

#[test]
fn unix_delivery_follows_ctrlc_termination() {
    for os in [OsSemantics::Linux, OsSemantics::MacOs] {
        register_test();
        set_os_semantics(os);
        let count = counting_handler();
        let termination = cfg!(feature = "ctrlc-termination");
        let caught = if termination {
            SignalDelivery::Handled
        } else {
            SignalDelivery::DefaultAction
        };
        assert_eq!(
            ctrlc::raise_signal(VirtualSignal::Interrupt),
            SignalDelivery::Handled
        );
        assert_eq!(
            ctrlc::raise_signal(VirtualSignal::Terminate),
            caught,
            "{os}"
        );
        assert_eq!(ctrlc::raise_signal(VirtualSignal::Hangup), caught, "{os}");
        assert_eq!(
            ctrlc::raise_signal(VirtualSignal::Close),
            SignalDelivery::Unavailable
        );
        assert!(ctrlc::raise());
        wait_for(&count, if termination { 4 } else { 2 });
    }
}

#[test]
fn windows_catches_every_console_event() {
    register_test();
    set_os_semantics(OsSemantics::Windows);
    let count = counting_handler();
    let expected = [
        (VirtualSignal::Interrupt, SignalDelivery::Handled),
        (VirtualSignal::Break, SignalDelivery::Handled),
        (VirtualSignal::Close, SignalDelivery::HandledThenExit),
        (VirtualSignal::Logoff, SignalDelivery::HandledThenExit),
        (VirtualSignal::Shutdown, SignalDelivery::HandledThenExit),
        (VirtualSignal::Terminate, SignalDelivery::Unavailable),
        (VirtualSignal::Hangup, SignalDelivery::Unavailable),
    ];
    for (sig, delivery) in expected {
        assert_eq!(ctrlc::raise_signal(sig), delivery, "{sig:?}");
    }
    assert!(ctrlc::raise());
    wait_for(&count, 6);
}

#[test]
fn a_thread_with_no_slot_takes_the_default_action() {
    let r = std::thread::spawn(|| ctrlc::raise_signal(VirtualSignal::Interrupt))
        .join()
        .unwrap();
    assert_eq!(r, SignalDelivery::DefaultAction);
}
