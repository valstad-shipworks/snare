//! Windows console control handlers and the CRT's signal table, per sim: registration order,
//! the thread each event is handled on, the close/logoff/shutdown time limits and the error codes.
#![cfg(windows)]

use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use snare::{RecordedEvent, Signal, SignalDelivery, SignalOrigin, Sim};

type Handler = unsafe extern "system" fn(u32) -> i32;

unsafe extern "system" {
    fn SetConsoleCtrlHandler(handler: Option<Handler>, add: i32) -> i32;
    fn GenerateConsoleCtrlEvent(event: u32, group: u32) -> i32;
    fn GetCurrentThreadId() -> u32;
    fn GetLastError() -> u32;
}

unsafe extern "C" {
    fn signal(sig: i32, handler: usize) -> usize;
    fn raise(sig: i32) -> i32;
}

const CTRL_BREAK_EVENT: u32 = 1;
const CTRL_CLOSE_EVENT: u32 = 2;
const SIGINT: i32 = 2;

fn set(handler: Option<Handler>, add: bool) -> i32 {
    // SAFETY: changes the sim's console table only.
    unsafe { SetConsoleCtrlHandler(handler, add as i32) }
}

static ORDER: Mutex<Vec<&str>> = Mutex::new(Vec::new());
unsafe extern "system" fn first(_: u32) -> i32 {
    ORDER.lock().unwrap().push("first");
    0
}
unsafe extern "system" fn second(_: u32) -> i32 {
    ORDER.lock().unwrap().push("second");
    1
}

#[test]
fn console_handler_lifo() {
    let sim = Sim::new();
    sim.run(|| {
        assert_eq!(set(Some(first), true), 1);
        assert_eq!(set(Some(second), true), 1);
        assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
        assert_eq!(
            *ORDER.lock().unwrap(),
            ["second"],
            "the last registered runs first"
        );
        assert_eq!(set(Some(second), false), 1);
        ORDER.lock().unwrap().clear();
        assert_eq!(
            sim.raise_signal(Signal::Break),
            SignalDelivery::DefaultAction
        );
        assert_eq!(*ORDER.lock().unwrap(), ["first"]);
    });
    assert!(sim.recorded_events().iter().any(|e| matches!(
        e.event,
        RecordedEvent::Signal {
            signal: Signal::Interrupt,
            origin: SignalOrigin::Sim,
            delivery: SignalDelivery::Handled
        }
    )));
}

static HANDLER_THREAD: AtomicU32 = AtomicU32::new(0);
unsafe extern "system" fn which_thread(_: u32) -> i32 {
    // SAFETY: no preconditions.
    HANDLER_THREAD.store(unsafe { GetCurrentThreadId() }, Ordering::SeqCst);
    1
}

#[test]
fn console_handler_new_thread() {
    let sim = Sim::new();
    sim.run(|| {
        set(Some(which_thread), true);
        assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
        // SAFETY: no preconditions.
        let me = unsafe { GetCurrentThreadId() };
        let on = HANDLER_THREAD.load(Ordering::SeqCst);
        assert!(on != 0 && on != me, "handled on a thread of its own");
    });
}

unsafe extern "system" fn slow_close(event: u32) -> i32 {
    if event == CTRL_CLOSE_EVENT {
        thread::sleep(Duration::from_secs(10));
    }
    1
}

#[test]
fn close_logoff_shutdown() {
    let sim = Sim::new();
    sim.run(|| {
        assert_eq!(
            sim.raise_signal(Signal::Close),
            SignalDelivery::DefaultAction
        );
        set(Some(slow_close), true);
        let start = Instant::now();
        assert_eq!(
            sim.raise_signal(Signal::Close),
            SignalDelivery::HandledThenExit
        );
        let waited = start.elapsed();
        assert!(
            waited >= Duration::from_secs(5) && waited < Duration::from_secs(6),
            "the close handler gets 5 s: {waited:?}"
        );
        for signal in [Signal::Logoff, Signal::Shutdown] {
            let delivery = sim.raise_signal(signal);
            assert!(
                matches!(
                    delivery,
                    SignalDelivery::HandledThenExit | SignalDelivery::Ignored
                ),
                "{signal:?}: {delivery:?}"
            );
        }
        assert_eq!(
            sim.raise_signal(Signal::Terminate),
            SignalDelivery::Unavailable
        );
    });
}

#[test]
fn remove_unregistered() {
    let sim = Sim::new();
    sim.run(|| {
        assert_eq!(set(Some(first), false), 0);
        // SAFETY: no preconditions.
        assert_eq!(unsafe { GetLastError() }, 87);
    });
}

static IGNORED: AtomicUsize = AtomicUsize::new(0);
unsafe extern "system" fn counted(_: u32) -> i32 {
    IGNORED.fetch_add(1, Ordering::SeqCst);
    1
}

#[test]
fn ignore_ctrl_c() {
    let sim = Sim::new();
    sim.run(|| {
        set(Some(counted), true);
        assert_eq!(set(None, true), 1);
        assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Ignored);
        assert_eq!(sim.raise_signal(Signal::Break), SignalDelivery::Handled);
        assert_eq!(set(None, false), 1);
        assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
        assert_eq!(IGNORED.load(Ordering::SeqCst), 2);
    });
}

static GENERATED: AtomicUsize = AtomicUsize::new(0);
unsafe extern "system" fn generated(event: u32) -> i32 {
    if event == CTRL_BREAK_EVENT {
        GENERATED.fetch_add(1, Ordering::SeqCst);
    }
    1
}

#[test]
fn generate_console_ctrl_event() {
    let sim = Sim::new();
    sim.run(|| {
        set(Some(generated), true);
        // SAFETY: delivered to this sim only.
        assert_eq!(unsafe { GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0) }, 1);
        while GENERATED.load(Ordering::SeqCst) == 0 {
            thread::sleep(Duration::from_millis(1));
        }
        // SAFETY: rejected before anything is delivered.
        assert_eq!(unsafe { GenerateConsoleCtrlEvent(CTRL_CLOSE_EVENT, 0) }, 0);
        // SAFETY: no preconditions.
        assert_eq!(unsafe { GetLastError() }, 87);
    });
    assert!(sim.recorded_events().iter().any(|e| matches!(
        e.event,
        RecordedEvent::Signal {
            signal: Signal::Break,
            origin: SignalOrigin::Process,
            ..
        }
    )));
}

static CRT: AtomicUsize = AtomicUsize::new(0);
extern "C" fn crt_handler(sig: i32) {
    assert_eq!(sig, SIGINT);
    CRT.fetch_add(1, Ordering::SeqCst);
}

#[test]
fn crt_signal() {
    let sim = Sim::new();
    sim.run(|| {
        // SAFETY: the CRT table of the sim only.
        unsafe {
            assert_eq!(signal(SIGINT, crt_handler as *const () as usize), 0);
            assert_eq!(raise(SIGINT), 0);
        }
        assert_eq!(CRT.load(Ordering::SeqCst), 1);
        assert_eq!(
            sim.raise_signal(Signal::Interrupt),
            SignalDelivery::DefaultAction,
            "the CRT reset its handler to SIG_DFL before calling it"
        );
        // SAFETY: as above.
        unsafe { signal(SIGINT, crt_handler as *const () as usize) };
        assert_eq!(sim.raise_signal(Signal::Interrupt), SignalDelivery::Handled);
        assert_eq!(CRT.load(Ordering::SeqCst), 2);
    });
}
