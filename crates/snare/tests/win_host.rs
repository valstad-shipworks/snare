#![cfg(windows)]
//! The Win32 scheduling hooks, driven through the real `SetThreadPriority`/`GetThreadPriority`
//! imports, resolve to the virtual `WinHost` inside a `Sim` — not to the real scheduler.

use snare::Sim;
use windows_sys::Win32::System::Threading::{
    GetCurrentThread, GetThreadPriority, SetThreadPriority, THREAD_PRIORITY_NORMAL,
};

#[test]
fn thread_priority_round_trips_through_the_interposer() {
    let sim = Sim::new();
    sim.run(|| {
        let thread = unsafe { GetCurrentThread() };

        // A freshly seen thread reads back the virtual host's default, THREAD_PRIORITY_NORMAL.
        assert_eq!(unsafe { GetThreadPriority(thread) }, THREAD_PRIORITY_NORMAL);

        // A value the real scheduler would reject: if the real API serviced this, SetThreadPriority
        // would fail and GetThreadPriority would never read it back. The virtual host stores it
        // verbatim, so the round-trip proves the call was simulated.
        const BOGUS: i32 = 12_345;
        assert_ne!(unsafe { SetThreadPriority(thread, BOGUS) }, 0);
        assert_eq!(unsafe { GetThreadPriority(thread) }, BOGUS);
    });
}
