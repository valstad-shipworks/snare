#![cfg(windows)]
//! The Win32 scheduling hooks, driven through the real `SetThreadPriority`/`GetThreadPriority`
//! imports, resolve to the virtual `WinHost` inside a `Sim` — not to the real scheduler.

use snare::Sim;
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, GetThreadPriority, SetThreadPriority, THREAD_PRIORITY_ABOVE_NORMAL,
    THREAD_PRIORITY_NORMAL,
};

#[test]
fn thread_priority_round_trips_through_the_interposer() {
    let sim = Sim::new();
    sim.run(|| {
        let thread = unsafe { GetCurrentThread() };

        assert_eq!(unsafe { GetThreadPriority(thread) }, THREAD_PRIORITY_NORMAL);
        assert_ne!(
            unsafe { SetThreadPriority(thread, THREAD_PRIORITY_ABOVE_NORMAL) },
            0
        );
        assert_eq!(
            unsafe { GetThreadPriority(thread) },
            THREAD_PRIORITY_ABOVE_NORMAL
        );
        assert_eq!(
            snare::real(|| unsafe { GetThreadPriority(thread) }),
            THREAD_PRIORITY_NORMAL
        );
    });
}
